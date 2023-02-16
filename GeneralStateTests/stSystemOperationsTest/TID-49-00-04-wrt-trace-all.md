> Status

| Status | Context |
| --- | --- |
| DONE | under WASM RT context |

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

* Following use-cases are failed, when executed with `const ENOUGH_GAS: Gas = Gas::new(99_900_000_000);`

> Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| TID-49-17 | stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth ( London::0, Merge::0 ) |
| TID-49-26 | stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance |

> Hit with `SYS_ILLEGAL_INSTRUCTION`, ExitCode::4

| Test ID | Use-Case |
| --- | --- |
| TID-49-30 | stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0 |

> Hit with `EVM_CONTRACT_BAD_JUMPDEST`, ExitCode::39

| Test ID | Use-Case |
| --- | --- |
| TID-49-35 | stSystemOperationsTest/CallToReturn1ForDynamicJump0 |
| TID-49-36 | stSystemOperationsTest/CallToReturn1ForDynamicJump1 |

> Hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION`, ExitCode::35

| Test ID | Use-Case |
| --- | --- |
| TID-49-09 | stSystemOperationsTest/callcodeTo0 |
| TID-49-10 | stSystemOperationsTest/callcodeToNameRegistrator0 |
| TID-49-11 | stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft |
| TID-49-12 | stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight |
| TID-49-13 | stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion |
| TID-49-14 | stSystemOperationsTest/callcodeToReturn1 |

> Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| TID-49-42 | stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0 |
| TID-49-43 | stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1 |

> Execution Trace

```
2023-02-06T02:14:14.303212Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stSystemOperationsTest", Total Files :: 67
2023-02-06T02:14:14.303479Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:14:14.332886Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:14.333036Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.333039Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:14.333092Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.333095Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:14.333156Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.333236Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:14.333239Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Istanbul::0
2023-02-06T02:14:14.333243Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:14:14.333246Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:14.694207Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:14:14.694226Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:14:14.694236Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:14.694240Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Berlin::0
2023-02-06T02:14:14.694242Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:14:14.694244Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:14.694375Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:14:14.694382Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:14:14.694389Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:14.694392Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::London::0
2023-02-06T02:14:14.694394Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:14:14.694397Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:14.694516Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:14:14.694523Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:14:14.694530Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:14.694532Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Merge::0
2023-02-06T02:14:14.694535Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:14:14.694537Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:14.694674Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:14:14.694680Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:14:14.696139Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:14:14.696169Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:14:14.722187Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:14.722300Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.722304Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:14.722359Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.722362Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:14.722423Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:14.722497Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:14.722500Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Istanbul::0
2023-02-06T02:14:14.722504Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:14:14.722506Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:15.186522Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:14:15.186543Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2088517500,
    events_root: None,
}
2023-02-06T02:14:15.190998Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:15.191008Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Berlin::0
2023-02-06T02:14:15.191012Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:14:15.191013Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:15.305397Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:14:15.305467Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-02-06T02:14:15.310665Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:15.310681Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::London::0
2023-02-06T02:14:15.310684Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:14:15.310687Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:15.424857Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:14:15.424965Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-02-06T02:14:15.429108Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:15.429117Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Merge::0
2023-02-06T02:14:15.429119Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:14:15.429121Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:15.544895Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:14:15.545003Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-02-06T02:14:15.562473Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:14:15.562520Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:14:15.587930Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:15.588028Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:15.588032Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:15.588082Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:15.588084Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:15.588139Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:15.588210Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:15.588213Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Istanbul::0
2023-02-06T02:14:15.588216Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:14:15.588217Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:16.084123Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:14:16.084142Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034834661,
    events_root: None,
}
2023-02-06T02:14:16.089818Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:16.089835Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Berlin::0
2023-02-06T02:14:16.089838Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:14:16.089840Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:16.244253Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:14:16.244292Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031711723,
    events_root: None,
}
2023-02-06T02:14:16.251257Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:16.251272Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::London::0
2023-02-06T02:14:16.251275Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:14:16.251277Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:16.392836Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:14:16.392856Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-02-06T02:14:16.400347Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:16.400364Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Merge::0
2023-02-06T02:14:16.400367Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:14:16.400369Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:16.540437Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:14:16.540476Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-02-06T02:14:16.565805Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:14:16.565847Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:14:16.591629Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:16.591736Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:16.591741Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:16.591807Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:16.591810Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:16.591882Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:16.591974Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:16.591979Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Istanbul::0
2023-02-06T02:14:16.591982Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:14:16.591986Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.085761Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:14:17.085782Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034834661,
    events_root: None,
}
2023-02-06T02:14:17.092145Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:17.092156Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Berlin::0
2023-02-06T02:14:17.092158Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:14:17.092160Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.227212Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:14:17.227232Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031711723,
    events_root: None,
}
2023-02-06T02:14:17.233727Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:17.233738Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::London::0
2023-02-06T02:14:17.233740Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:14:17.233741Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.363494Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:14:17.363532Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-02-06T02:14:17.370256Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:17.370267Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Merge::0
2023-02-06T02:14:17.370269Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:14:17.370271Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.501411Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:14:17.501449Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-02-06T02:14:17.520011Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:14:17.520049Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:14:17.543648Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:17.543747Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.543750Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:17.543799Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.543801Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:17.543855Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.543929Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:17.543932Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Istanbul::0
2023-02-06T02:14:17.543935Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:14:17.543937Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.887448Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:14:17.887468Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631129,
    events_root: None,
}
2023-02-06T02:14:17.887478Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:17.887481Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Berlin::0
2023-02-06T02:14:17.887483Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:14:17.887484Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.887582Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:14:17.887588Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:17.887592Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:17.887593Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::London::0
2023-02-06T02:14:17.887595Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:14:17.887597Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.887666Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:14:17.887671Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:17.887675Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:17.887677Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Merge::0
2023-02-06T02:14:17.887679Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:14:17.887681Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:17.887746Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:14:17.887751Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:17.888405Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:14:17.888427Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:14:17.912878Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:17.912978Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.912982Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:17.913033Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.913035Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:17.913092Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:17.913163Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:17.913166Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::0
2023-02-06T02:14:17.913169Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:17.913171Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265117Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265137Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:14:18.265148Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 1
2023-02-06T02:14:18.265151Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::1
2023-02-06T02:14:18.265152Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265154Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265318Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265325Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:14:18.265331Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:18.265333Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::0
2023-02-06T02:14:18.265335Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265336Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265471Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265476Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:14:18.265482Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 1
2023-02-06T02:14:18.265483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::1
2023-02-06T02:14:18.265485Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265487Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265603Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265609Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:14:18.265615Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:18.265617Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::0
2023-02-06T02:14:18.265619Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265620Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265736Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265741Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:14:18.265747Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 1
2023-02-06T02:14:18.265749Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::1
2023-02-06T02:14:18.265750Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265752Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265866Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265871Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:14:18.265876Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:18.265878Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::0
2023-02-06T02:14:18.265880Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.265882Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.265994Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.265999Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:14:18.266005Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 1
2023-02-06T02:14:18.266008Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::1
2023-02-06T02:14:18.266009Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:14:18.266011Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:14:18.266132Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:14:18.266137Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:14:18.266860Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:14:18.266880Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:14:18.291047Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:18.291152Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.291156Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:18.291205Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.291207Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:18.291261Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.291338Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:18.291341Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Istanbul::0
2023-02-06T02:14:18.291343Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:14:18.291345Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:18.639591Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:14:18.639609Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25719303,
    events_root: None,
}
2023-02-06T02:14:18.639649Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:18.639653Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Berlin::0
2023-02-06T02:14:18.639655Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:14:18.639657Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:18.641019Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:14:18.641026Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:14:18.641060Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:18.641063Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::London::0
2023-02-06T02:14:18.641064Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:14:18.641066Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:18.642435Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:14:18.642442Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:14:18.642475Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:18.642478Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Merge::0
2023-02-06T02:14:18.642480Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:14:18.642482Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:18.643835Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:14:18.643842Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:14:18.645013Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:14:18.645041Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:14:18.673848Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:18.673963Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.673966Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:18.674019Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.674021Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:18.674078Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:18.674152Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:18.674156Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Istanbul::0
2023-02-06T02:14:18.674160Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:14:18.674162Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.061483Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:14:19.061501Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:19.061620Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:19.061623Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Berlin::0
2023-02-06T02:14:19.061625Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:14:19.061627Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.065757Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:14:19.065765Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:19.065883Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:19.065886Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::London::0
2023-02-06T02:14:19.065887Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:14:19.065889Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.069925Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:14:19.069933Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:19.070056Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:19.070058Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Merge::0
2023-02-06T02:14:19.070060Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:14:19.070062Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.074221Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:14:19.074231Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:19.075640Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:14:19.075671Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.099658Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:19.099756Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:19.099759Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:19.099810Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:19.099881Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:19.099883Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Istanbul::0
2023-02-06T02:14:19.099887Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.099889Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.585964Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:14:19.585985Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3403480531,
    events_root: None,
}
2023-02-06T02:14:19.593152Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:19.593165Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Berlin::0
2023-02-06T02:14:19.593167Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.593170Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.593758Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:14:19.593769Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6916483,
    events_root: None,
}
2023-02-06T02:14:19.593779Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:19.593781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::London::0
2023-02-06T02:14:19.593783Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.593785Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.593910Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:14:19.593918Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1839871,
    events_root: None,
}
2023-02-06T02:14:19.593921Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:19.593933Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:19.593935Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Merge::0
2023-02-06T02:14:19.593937Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.593939Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:19.594051Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:14:19.594056Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1839871,
    events_root: None,
}
2023-02-06T02:14:19.594060Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:19.606512Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:14:19.606559Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:14:19.630514Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:19.630614Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:19.630618Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:19.630670Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:19.630742Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:19.630745Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Istanbul::0
2023-02-06T02:14:19.630748Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:14:19.630749Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:20.118476Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:14:20.118495Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368215765,
    events_root: None,
}
2023-02-06T02:14:20.125442Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:20.125454Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Berlin::0
2023-02-06T02:14:20.125457Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:14:20.125459Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:20.293820Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:14:20.293848Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107212,
    events_root: None,
}
2023-02-06T02:14:20.299785Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:20.299797Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::London::0
2023-02-06T02:14:20.299800Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:14:20.299802Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:20.476252Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:14:20.476282Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306106936,
    events_root: None,
}
2023-02-06T02:14:20.482102Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:20.482118Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Merge::0
2023-02-06T02:14:20.482120Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:14:20.482122Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:20.653591Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:14:20.653620Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107120,
    events_root: None,
}
2023-02-06T02:14:20.677646Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:14:20.677711Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:14:20.701606Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:20.701708Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:20.701712Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:20.701763Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:20.701833Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:20.701836Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Istanbul::0
2023-02-06T02:14:20.701840Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:14:20.701841Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:21.185312Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:14:21.185329Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368215765,
    events_root: None,
}
2023-02-06T02:14:21.193244Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:21.193257Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Berlin::0
2023-02-06T02:14:21.193260Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:14:21.193262Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:21.355376Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:14:21.355406Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107212,
    events_root: None,
}
2023-02-06T02:14:21.360810Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:21.360824Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::London::0
2023-02-06T02:14:21.360827Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:14:21.360829Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:21.532889Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:14:21.532916Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306106936,
    events_root: None,
}
2023-02-06T02:14:21.537936Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:21.537947Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Merge::0
2023-02-06T02:14:21.537949Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:14:21.537951Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:21.702061Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:14:21.702091Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107120,
    events_root: None,
}
2023-02-06T02:14:21.723419Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:14:21.723458Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:14:21.747275Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:21.747373Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:21.747377Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:21.747429Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:21.747501Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:21.747504Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Istanbul::0
2023-02-06T02:14:21.747507Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:14:21.747509Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:22.218842Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:14:22.218860Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368114727,
    events_root: None,
}
2023-02-06T02:14:22.225739Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:22.225748Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Berlin::0
2023-02-06T02:14:22.225751Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:14:22.225753Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:22.390674Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:14:22.390703Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006359,
    events_root: None,
}
2023-02-06T02:14:22.396556Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:22.396611Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::London::0
2023-02-06T02:14:22.396622Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:14:22.396629Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:22.567292Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:14:22.567322Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006451,
    events_root: None,
}
2023-02-06T02:14:22.572323Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:22.572337Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Merge::0
2023-02-06T02:14:22.572340Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:14:22.572343Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:22.738460Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:14:22.738491Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006267,
    events_root: None,
}
2023-02-06T02:14:22.760612Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:14:22.760656Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:14:22.784998Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:22.785104Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:22.785108Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:22.785160Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:22.785163Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:22.785220Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:22.785301Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:22.785305Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Istanbul::0
2023-02-06T02:14:22.785309Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:14:22.785311Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.151818Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:14:23.151837Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.151963Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:23.151967Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Berlin::0
2023-02-06T02:14:23.151971Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:14:23.151973Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.156227Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:14:23.156235Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.156356Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:23.156359Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::London::0
2023-02-06T02:14:23.156362Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:14:23.156364Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.160567Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:14:23.160575Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.160698Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:23.160701Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Merge::0
2023-02-06T02:14:23.160703Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:14:23.160707Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.164866Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:14:23.164874Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.166215Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:14:23.166244Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:14:23.190126Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:23.190228Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.190232Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:23.190284Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.190286Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:23.190343Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.190416Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:23.190419Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Istanbul::0
2023-02-06T02:14:23.190423Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:14:23.190426Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.550638Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:14:23.550656Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.550834Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:23.550839Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Berlin::0
2023-02-06T02:14:23.550842Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:14:23.550844Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.556155Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:14:23.556168Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.556300Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:23.556304Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::London::0
2023-02-06T02:14:23.556306Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:14:23.556307Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.561563Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:14:23.561581Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.561757Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:23.561763Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Merge::0
2023-02-06T02:14:23.561766Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:14:23.561768Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.567124Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:14:23.567142Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:14:23.568594Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:14:23.568628Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:14:23.593786Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:23.593895Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.593898Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:23.593950Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.593952Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:23.594019Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.594097Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:23.594100Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Istanbul::0
2023-02-06T02:14:23.594103Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:14:23.594106Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.944457Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:14:23.944476Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:14:23.944486Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:23.944490Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Berlin::0
2023-02-06T02:14:23.944492Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:14:23.944494Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.944617Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:14:23.944624Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:14:23.944629Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:23.944631Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::London::0
2023-02-06T02:14:23.944633Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:14:23.944635Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.944749Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:14:23.944755Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:14:23.944760Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:23.944762Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Merge::0
2023-02-06T02:14:23.944764Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:14:23.944765Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:23.944882Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:14:23.944888Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:14:23.945788Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:14:23.945820Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:23.971929Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:23.972035Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.972038Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:23.972091Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.972093Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:23.972151Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:23.972225Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:23.972228Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Istanbul::0
2023-02-06T02:14:23.972232Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:23.972234Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.312479Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:14:24.312498Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:14:24.312507Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:24.312511Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Berlin::0
2023-02-06T02:14:24.312513Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:24.312515Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.312665Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:14:24.312673Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:14:24.312680Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:24.312683Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::London::0
2023-02-06T02:14:24.312686Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:24.312689Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.312841Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:14:24.312848Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:14:24.312853Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:24.312855Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Merge::0
2023-02-06T02:14:24.312857Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:24.312860Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.312972Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:14:24.312978Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:14:24.313639Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:14:24.313660Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.339805Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:24.339910Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.339914Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:24.339966Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.339968Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:24.340026Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.340106Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:24.340111Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Istanbul::0
2023-02-06T02:14:24.340115Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.340117Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.697761Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:14:24.697782Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006546,
    events_root: None,
}
2023-02-06T02:14:24.697793Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:24.697797Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Berlin::0
2023-02-06T02:14:24.697800Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.697803Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.697981Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:14:24.697989Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:14:24.697996Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:24.698000Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::London::0
2023-02-06T02:14:24.698003Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.698007Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.698154Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:14:24.698162Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:14:24.698168Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:24.698170Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Merge::0
2023-02-06T02:14:24.698173Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.698176Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:24.698306Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:14:24.698312Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:14:24.699255Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:14:24.699299Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:24.724072Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:24.724175Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.724178Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:24.724229Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.724231Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:24.724289Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:24.724360Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:24.724363Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Istanbul::0
2023-02-06T02:14:24.724368Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:24.724370Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.088509Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:14:25.088532Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:14:25.088538Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:25.088552Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:25.088555Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Berlin::0
2023-02-06T02:14:25.088557Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:25.088559Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.088685Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:14:25.088691Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:14:25.088694Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:25.088704Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:25.088706Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::London::0
2023-02-06T02:14:25.088708Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:25.088710Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.088800Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:14:25.088806Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:14:25.088808Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:25.088817Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:25.088819Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Merge::0
2023-02-06T02:14:25.088822Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:25.088824Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.088912Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:14:25.088919Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:14:25.088922Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:25.089585Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:14:25.089613Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.116102Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:25.116206Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.116209Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:25.116260Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.116262Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:25.116319Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.116392Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:25.116394Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Istanbul::0
2023-02-06T02:14:25.116398Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.116399Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.458544Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:14:25.458562Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:14:25.458572Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:25.458576Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Berlin::0
2023-02-06T02:14:25.458578Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.458580Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.458703Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:14:25.458710Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:14:25.458717Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:25.458719Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::London::0
2023-02-06T02:14:25.458722Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.458724Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.458835Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:14:25.458841Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:14:25.458846Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:25.458848Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Merge::0
2023-02-06T02:14:25.458850Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.458851Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.458956Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:14:25.458963Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:14:25.459660Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:14:25.459685Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.483807Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:25.483904Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.483907Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:25.483955Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.483957Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:25.484011Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.484081Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:25.484084Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Istanbul::0
2023-02-06T02:14:25.484087Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.484089Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.841663Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:14:25.841683Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:14:25.841692Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:25.841695Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Berlin::0
2023-02-06T02:14:25.841697Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.841700Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.841827Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:14:25.841834Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:14:25.841840Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:25.841842Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::London::0
2023-02-06T02:14:25.841844Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.841846Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.841960Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:14:25.841965Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:14:25.841971Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:25.841973Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Merge::0
2023-02-06T02:14:25.841975Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.841977Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:25.842087Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:14:25.842093Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:14:25.842951Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:14:25.842979Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:25.868802Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:25.868907Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.868910Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:25.868963Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.868965Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:25.869024Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:25.869100Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:25.869105Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Istanbul::0
2023-02-06T02:14:25.869109Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:25.869112Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.232293Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:14:26.232312Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:14:26.232322Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:26.232326Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Berlin::0
2023-02-06T02:14:26.232328Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:26.232330Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.232455Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:14:26.232462Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:14:26.232467Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:26.232469Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::London::0
2023-02-06T02:14:26.232471Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:26.232472Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.232614Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:14:26.232620Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:14:26.232625Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:26.232627Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Merge::0
2023-02-06T02:14:26.232629Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:26.232631Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.232740Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:14:26.232746Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:14:26.233573Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:14:26.233603Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.258179Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:26.258288Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.258292Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:26.258344Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.258346Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:26.258406Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.258478Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:26.258481Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Istanbul::0
2023-02-06T02:14:26.258484Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.258486Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.626056Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:14:26.626074Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-02-06T02:14:26.626079Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:26.626092Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:26.626095Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Berlin::0
2023-02-06T02:14:26.626097Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.626099Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.626222Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:14:26.626228Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-02-06T02:14:26.626231Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:26.626239Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:26.626241Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::London::0
2023-02-06T02:14:26.626243Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.626245Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.626332Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:14:26.626337Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-02-06T02:14:26.626340Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:26.626348Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:26.626350Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Merge::0
2023-02-06T02:14:26.626352Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.626354Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.626447Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:14:26.626454Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-02-06T02:14:26.626458Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:26.627294Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:14:26.627325Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:26.652395Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:26.652508Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.652512Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:26.652564Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.652567Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:26.652623Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:26.652697Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:26.652700Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Istanbul::0
2023-02-06T02:14:26.652703Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:26.652705Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:26.996259Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:14:26.996280Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-02-06T02:14:26.996293Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:26.996297Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Berlin::0
2023-02-06T02:14:26.996299Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:26.996301Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.001338Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:14:27.001356Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-02-06T02:14:27.001367Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:27.001370Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::London::0
2023-02-06T02:14:27.001372Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:27.001375Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.006388Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:14:27.006405Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-02-06T02:14:27.006416Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:27.006420Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Merge::0
2023-02-06T02:14:27.006422Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:27.006424Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.011394Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:14:27.011411Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-02-06T02:14:27.012285Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:14:27.012312Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.036920Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:27.037056Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.037062Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:27.037120Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.037122Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:27.037182Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.037261Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:27.037264Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Istanbul::0
2023-02-06T02:14:27.037267Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.037275Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.391713Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:14:27.391731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:14:27.391741Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:27.391745Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Berlin::0
2023-02-06T02:14:27.391746Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.391748Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.392070Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:14:27.392077Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:14:27.392083Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:27.392085Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::London::0
2023-02-06T02:14:27.392087Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.392089Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.392402Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:14:27.392408Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:14:27.392413Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:27.392416Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Merge::0
2023-02-06T02:14:27.392417Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.392419Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.392708Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:14:27.392713Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:14:27.393320Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:14:27.393348Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.417553Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:27.417652Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.417655Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:27.417705Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.417707Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:27.417762Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.417833Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:27.417836Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:14:27.417839Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.417842Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763190Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763211Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763220Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:27.763223Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:14:27.763225Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763227Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763356Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763362Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763368Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:27.763370Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:14:27.763372Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763375Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763484Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763489Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763495Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:27.763496Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:14:27.763499Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763500Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763606Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763611Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763616Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:27.763619Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:14:27.763620Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763623Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763727Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763732Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763737Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:27.763739Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:14:27.763741Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763743Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763847Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763853Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763858Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:27.763859Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:14:27.763861Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763863Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.763967Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.763972Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.763977Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:27.763979Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:14:27.763981Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.763983Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:27.764092Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:14:27.764097Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:14:27.764713Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:14:27.764733Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:14:27.788981Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:27.789110Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.789115Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:27.789187Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.789190Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:27.789270Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:27.789361Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:27.789365Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Istanbul::0
2023-02-06T02:14:27.789368Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:14:27.789370Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.138547Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:14:28.138565Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:14:28.138575Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:28.138578Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Berlin::0
2023-02-06T02:14:28.138580Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:14:28.138582Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.138730Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:14:28.138737Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:14:28.138742Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:28.138744Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::London::0
2023-02-06T02:14:28.138746Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:14:28.138747Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.138876Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:14:28.138882Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:14:28.138887Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:28.138889Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Merge::0
2023-02-06T02:14:28.138891Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:14:28.138893Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.139000Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:14:28.139006Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:14:28.139671Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:14:28.139697Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.164227Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:28.164328Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.164332Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:28.164384Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.164386Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:28.164442Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.164515Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:28.164518Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Istanbul::0
2023-02-06T02:14:28.164522Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.164523Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.524877Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:14:28.524895Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:14:28.524900Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.524915Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:28.524919Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Berlin::0
2023-02-06T02:14:28.524922Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.524924Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.525055Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:14:28.525063Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:14:28.525067Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.525078Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:28.525083Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::London::0
2023-02-06T02:14:28.525085Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.525088Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.525213Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:14:28.525220Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:14:28.525223Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.525232Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:28.525234Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Merge::0
2023-02-06T02:14:28.525236Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.525238Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.525361Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:14:28.525367Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:14:28.525370Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.526040Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:14:28.526065Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.553228Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:28.553349Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.553352Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:28.553405Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.553408Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:28.553466Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.553542Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:28.553545Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Istanbul::0
2023-02-06T02:14:28.553549Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.553551Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.941771Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:14:28.941790Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:14:28.941795Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.941809Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:28.941812Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Berlin::0
2023-02-06T02:14:28.941814Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.941816Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.941987Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:14:28.941995Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:14:28.941998Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.942010Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:28.942013Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::London::0
2023-02-06T02:14:28.942016Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.942018Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.942139Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:14:28.942146Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:14:28.942148Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.942157Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:28.942159Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Merge::0
2023-02-06T02:14:28.942161Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.942163Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:28.942274Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:14:28.942280Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:14:28.942283Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:28.943002Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:14:28.943022Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:14:28.969200Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:28.969314Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.969317Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:28.969371Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.969374Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:28.969432Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:28.969505Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:28.969508Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Istanbul::0
2023-02-06T02:14:28.969511Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:14:28.969513Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:29.311405Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:14:29.311422Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:14:29.311432Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:29.311435Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Berlin::0
2023-02-06T02:14:29.311437Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:14:29.311438Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:29.311565Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:14:29.311572Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:14:29.311578Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:29.311579Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::London::0
2023-02-06T02:14:29.311581Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:14:29.311582Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:29.311725Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:14:29.311747Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:14:29.311754Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:29.311757Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Merge::0
2023-02-06T02:14:29.311760Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:14:29.311762Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:29.311898Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:14:29.311904Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:14:29.312576Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:14:29.312595Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:14:29.338124Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:29.338231Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:29.338234Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:29.338288Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:29.338290Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:29.338348Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:29.338421Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:29.338424Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Istanbul::0
2023-02-06T02:14:29.338427Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:14:29.338429Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:29.812259Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:14:29.812276Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3909237,
    events_root: None,
}
2023-02-06T02:14:29.812292Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:29.812295Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Berlin::0
2023-02-06T02:14:29.812297Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:14:29.812300Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:29.978444Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:14:29.978458Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13534900,
    events_root: None,
}
2023-02-06T02:14:29.978484Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:29.978488Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::London::0
2023-02-06T02:14:29.978491Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:14:29.978494Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:29.979135Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:14:29.979144Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-02-06T02:14:29.979162Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:29.979165Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Merge::0
2023-02-06T02:14:29.979167Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:14:29.979170Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:29.979772Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:14:29.979779Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-02-06T02:14:29.980689Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:14:29.980721Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:14:30.005789Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:30.005891Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.005894Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:30.005951Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.005953Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:30.006013Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.006086Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:30.006090Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Istanbul::0
2023-02-06T02:14:30.006093Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:14:30.006096Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:30.354268Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:14:30.354288Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2702051,
    events_root: None,
}
2023-02-06T02:14:30.354299Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:30.354303Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Berlin::0
2023-02-06T02:14:30.354304Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:14:30.354306Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:30.354440Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:14:30.354447Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:14:30.354452Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:30.354455Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::London::0
2023-02-06T02:14:30.354456Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:14:30.354458Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:30.354575Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:14:30.354582Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:14:30.354587Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:30.354589Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Merge::0
2023-02-06T02:14:30.354591Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:14:30.354592Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:30.354707Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:14:30.354712Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:14:30.355364Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:14:30.355394Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:14:30.380320Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:30.380422Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.380425Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:30.380477Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.380549Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:30.380551Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Istanbul::0
2023-02-06T02:14:30.380554Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:14:30.380556Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:14:30.762353Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:14:30.762375Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2563734,
    events_root: None,
}
2023-02-06T02:14:30.762385Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:30.762389Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Berlin::0
2023-02-06T02:14:30.762391Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:14:30.762393Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:14:30.762510Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:14:30.762516Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:14:30.762521Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:30.762522Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::London::0
2023-02-06T02:14:30.762524Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:14:30.762526Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:14:30.762614Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:14:30.762619Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:14:30.762625Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:30.762627Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Merge::0
2023-02-06T02:14:30.762629Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:14:30.762632Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:14:30.762717Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:14:30.762721Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:14:30.763399Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:14:30.763420Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:14:30.788284Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:30.788387Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.788390Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:30.788443Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:30.788516Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:30.788519Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Istanbul::0
2023-02-06T02:14:30.788523Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:14:30.788525Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.144572Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:14:31.144597Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:14:31.144605Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:31.144609Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Berlin::0
2023-02-06T02:14:31.144611Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:14:31.144612Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.144769Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:14:31.144776Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:14:31.144781Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:31.144782Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::London::0
2023-02-06T02:14:31.144784Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:14:31.144787Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.144891Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:14:31.144897Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:14:31.144901Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:31.144903Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Merge::0
2023-02-06T02:14:31.144905Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:14:31.144907Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.145010Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:14:31.145015Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:14:31.145610Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:14:31.145636Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:14:31.170246Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:31.170351Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.170355Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:31.170409Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.170483Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:31.170485Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Istanbul::0
2023-02-06T02:14:31.170489Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:14:31.170491Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.509877Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:14:31.509897Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:14:31.509907Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:31.509910Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Berlin::0
2023-02-06T02:14:31.509911Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:14:31.509913Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.510018Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:14:31.510023Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:14:31.510028Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:31.510029Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::London::0
2023-02-06T02:14:31.510031Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:14:31.510033Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.510118Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:14:31.510123Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:14:31.510128Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:31.510130Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Merge::0
2023-02-06T02:14:31.510132Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:14:31.510134Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.510218Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:14:31.510223Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:14:31.510939Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:14:31.510968Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:14:31.538730Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:31.538834Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.538837Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:31.538893Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.538965Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:31.538968Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Istanbul::0
2023-02-06T02:14:31.538971Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:14:31.538973Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.906748Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:14:31.906771Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:14:31.906776Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:31.906790Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:31.906794Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Berlin::0
2023-02-06T02:14:31.906796Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:14:31.906797Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.906922Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:14:31.906928Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:14:31.906931Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:31.906940Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:31.906942Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::London::0
2023-02-06T02:14:31.906943Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:14:31.906945Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.907038Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:14:31.907043Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:14:31.907046Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:31.907054Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:31.907056Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Merge::0
2023-02-06T02:14:31.907058Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:14:31.907059Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:31.907149Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:14:31.907154Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:14:31.907157Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:31.907874Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:14:31.907920Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:14:31.935354Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:31.935465Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.935469Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:31.935542Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.935546Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:31.935622Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:31.935726Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:31.935731Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Istanbul::0
2023-02-06T02:14:31.935735Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:14:31.935738Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.271152Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:14:32.271171Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:32.271176Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.271190Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:32.271194Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Berlin::0
2023-02-06T02:14:32.271195Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:14:32.271197Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.271324Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:14:32.271331Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:32.271333Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.271342Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:32.271344Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::London::0
2023-02-06T02:14:32.271345Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:14:32.271347Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.271439Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:14:32.271445Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:32.271448Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.271456Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:32.271458Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Merge::0
2023-02-06T02:14:32.271460Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:14:32.271462Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.271550Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:14:32.271557Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:32.271560Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.272187Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:14:32.272208Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.297249Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:32.297364Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.297369Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:32.297425Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.297428Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:32.297490Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.297565Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:32.297569Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Istanbul::0
2023-02-06T02:14:32.297573Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.297577Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.641030Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:14:32.641052Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:32.641057Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.641071Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:32.641075Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Berlin::0
2023-02-06T02:14:32.641077Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.641079Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.641187Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:14:32.641194Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:32.641197Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.641205Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:32.641207Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::London::0
2023-02-06T02:14:32.641209Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.641211Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.641312Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:14:32.641318Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:32.641321Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.641330Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:32.641332Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Merge::0
2023-02-06T02:14:32.641334Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.641336Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:32.641423Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:14:32.641429Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:32.641432Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:32.642317Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:14:32.642338Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:32.667415Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:32.667520Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.667523Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:32.667575Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.667577Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:32.667634Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:32.667706Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:32.667709Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Istanbul::0
2023-02-06T02:14:32.667713Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:32.667715Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.019761Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:14:33.019781Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:33.019787Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.019800Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:33.019803Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Berlin::0
2023-02-06T02:14:33.019805Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:33.019807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.019930Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:14:33.019936Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:33.019939Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.019949Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:33.019951Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::London::0
2023-02-06T02:14:33.019953Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:33.019955Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.020045Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:14:33.020051Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:33.020054Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.020062Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:33.020064Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Merge::0
2023-02-06T02:14:33.020066Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:33.020068Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.020157Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:14:33.020163Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:14:33.020165Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.020815Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:14:33.020843Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.045352Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:33.045448Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.045451Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:33.045501Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.045503Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:33.045558Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.045629Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:33.045632Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:14:33.045635Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.045637Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388139Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388157Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388162Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388175Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:33.388178Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:14:33.388180Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388182Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388291Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388297Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388300Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388308Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:33.388310Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:14:33.388312Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388314Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388401Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388408Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388410Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388419Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:33.388420Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:14:33.388423Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388425Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388511Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388517Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388520Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388528Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:33.388530Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:14:33.388532Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388534Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388620Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388625Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388629Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388637Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:33.388638Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:14:33.388640Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388643Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388736Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388742Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388746Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388756Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:33.388758Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:14:33.388761Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388764Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388871Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.388878Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.388881Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.388892Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:33.388894Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:14:33.388897Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.388900Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.388998Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:14:33.389004Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.389007Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.389650Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:14:33.389676Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:14:33.414509Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:33.414617Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.414621Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:33.414683Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.414687Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:33.414762Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.414857Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:33.414862Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Istanbul::0
2023-02-06T02:14:33.414865Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:14:33.414868Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.769651Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:14:33.769671Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.769676Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.769689Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:33.769692Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Berlin::0
2023-02-06T02:14:33.769694Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:14:33.769696Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.769839Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:14:33.769847Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.769850Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.769861Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:33.769863Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::London::0
2023-02-06T02:14:33.769866Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:14:33.769868Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.769977Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:14:33.769983Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.769987Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.769997Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:33.770000Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Merge::0
2023-02-06T02:14:33.770002Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:14:33.770004Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:33.770102Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:14:33.770109Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:14:33.770112Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:33.770733Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:14:33.770754Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:14:33.795251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:33.795351Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.795354Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:33.795406Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:33.795479Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:33.795482Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Istanbul::0
2023-02-06T02:14:33.795485Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:14:33.795487Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:34.172661Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:14:34.172679Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2479617,
    events_root: None,
}
2023-02-06T02:14:34.172689Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:34.172693Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Berlin::0
2023-02-06T02:14:34.172694Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:14:34.172696Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:34.172829Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:14:34.172835Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:14:34.172840Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:34.172842Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::London::0
2023-02-06T02:14:34.172843Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:14:34.172845Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:34.172937Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:14:34.172943Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:14:34.172948Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:34.172949Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Merge::0
2023-02-06T02:14:34.172951Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:14:34.172953Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:34.173051Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:14:34.173057Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:14:34.173783Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:14:34.173806Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:14:34.199187Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:34.199290Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:34.199293Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:34.199348Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:34.199421Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:34.199424Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Istanbul::0
2023-02-06T02:14:34.199427Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:14:34.199429Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:14:34.846710Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:14:34.846726Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14635493,
    events_root: None,
}
2023-02-06T02:14:34.846773Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:34.846783Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Berlin::0
2023-02-06T02:14:34.846791Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:14:34.846798Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:34.847598Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:14:34.847610Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13552078,
    events_root: None,
}
2023-02-06T02:14:34.847631Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:34.847645Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::London::0
2023-02-06T02:14:34.847652Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:14:34.847660Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:34.848403Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:14:34.848423Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-02-06T02:14:34.848451Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:34.848459Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Merge::0
2023-02-06T02:14:34.848466Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:14:34.848474Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:34.849246Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:14:34.849264Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-02-06T02:14:34.850482Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:14:34.850516Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:34.875859Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:34.875962Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:34.875965Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:34.876021Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:34.876094Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:34.876097Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Istanbul::0
2023-02-06T02:14:34.876101Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:34.876103Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.222211Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:14:35.222232Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:14:35.222242Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:35.222245Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Berlin::0
2023-02-06T02:14:35.222247Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:35.222249Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.222356Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:14:35.222362Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:14:35.222367Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:35.222368Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::London::0
2023-02-06T02:14:35.222371Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:35.222372Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.222460Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:14:35.222465Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:14:35.222470Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:35.222471Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Merge::0
2023-02-06T02:14:35.222473Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:35.222475Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.222563Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:14:35.222568Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:14:35.223177Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:14:35.223213Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.247245Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:35.247346Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:35.247349Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:35.247400Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:35.247472Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:35.247474Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Istanbul::0
2023-02-06T02:14:35.247478Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.247480Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.620406Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:14:35.620426Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:14:35.620431Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.620444Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:35.620447Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Berlin::0
2023-02-06T02:14:35.620449Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.620451Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.620558Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:14:35.620565Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:14:35.620569Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.620578Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:35.620579Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::London::0
2023-02-06T02:14:35.620581Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.620583Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.620674Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:14:35.620681Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:14:35.620684Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.620695Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:35.620697Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Merge::0
2023-02-06T02:14:35.620700Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.620703Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.620813Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:14:35.620820Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:14:35.620822Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.621488Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:14:35.621509Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.645374Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:35.645475Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:35.645479Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:35.645530Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:35.645601Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:35.645604Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Istanbul::0
2023-02-06T02:14:35.645608Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.645610Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.992348Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:14:35.992369Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:14:35.992374Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.992389Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:35.992394Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Berlin::0
2023-02-06T02:14:35.992396Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.992399Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.992504Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:14:35.992510Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:14:35.992513Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.992522Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:35.992523Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::London::0
2023-02-06T02:14:35.992525Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.992527Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.992621Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:14:35.992627Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:14:35.992630Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.992638Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:35.992640Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Merge::0
2023-02-06T02:14:35.992642Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.992645Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:35.992747Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:14:35.992753Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:14:35.992756Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:14:35.993495Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:14:35.993517Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.017720Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:36.017820Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:36.017823Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:36.017875Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:36.017946Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:36.017949Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Istanbul::0
2023-02-06T02:14:36.017952Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.017954Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:36.360635Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:14:36.360655Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:14:36.360665Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:36.360668Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Berlin::0
2023-02-06T02:14:36.360670Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.360672Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:36.360779Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:14:36.360786Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:14:36.360790Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:36.360792Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::London::0
2023-02-06T02:14:36.360794Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.360796Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:36.360888Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:14:36.360893Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:14:36.360897Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:36.360900Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Merge::0
2023-02-06T02:14:36.360902Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.360904Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:36.360992Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:14:36.360997Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:14:36.361644Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:14:36.361670Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:14:36.386712Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:36.386816Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:36.386820Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:36.386891Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:36.387001Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:36.387005Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Istanbul::0
2023-02-06T02:14:36.387009Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:14:36.387012Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:14:37.000603Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:14:37.000616Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14574187,
    events_root: None,
}
2023-02-06T02:14:37.000641Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:37.000644Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Berlin::0
2023-02-06T02:14:37.000646Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:14:37.000648Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:37.001265Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:14:37.001279Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13489689,
    events_root: None,
}
2023-02-06T02:14:37.001295Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:37.001297Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::London::0
2023-02-06T02:14:37.001299Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:14:37.001301Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:37.001850Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:14:37.001857Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14408087,
    events_root: None,
}
2023-02-06T02:14:37.001874Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:37.001876Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Merge::0
2023-02-06T02:14:37.001879Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:14:37.001881Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:37.002449Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:14:37.002456Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14925859,
    events_root: None,
}
2023-02-06T02:14:37.003506Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:14:37.003535Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.031645Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:37.031806Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:37.031812Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:37.031882Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:37.031977Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:37.031992Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Istanbul::0
2023-02-06T02:14:37.032002Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.032005Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:14:37.635040Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:14:37.635053Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14575662,
    events_root: None,
}
2023-02-06T02:14:37.635078Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:37.635081Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Berlin::0
2023-02-06T02:14:37.635083Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.635085Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:37.635707Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:14:37.635714Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13491163,
    events_root: None,
}
2023-02-06T02:14:37.635730Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:37.635732Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::London::0
2023-02-06T02:14:37.635735Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.635737Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:37.636281Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:14:37.636289Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14409562,
    events_root: None,
}
2023-02-06T02:14:37.636306Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:37.636308Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Merge::0
2023-02-06T02:14:37.636310Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.636312Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:37.636882Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:14:37.636889Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14927334,
    events_root: None,
}
2023-02-06T02:14:37.637780Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:14:37.637804Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:37.661909Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:37.662008Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:37.662012Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:37.662063Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:37.662135Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:37.662138Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Istanbul::0
2023-02-06T02:14:37.662141Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:37.662143Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:14:38.262989Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:14:38.263002Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14574187,
    events_root: None,
}
2023-02-06T02:14:38.263027Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:38.263031Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Berlin::0
2023-02-06T02:14:38.263033Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:38.263036Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:38.263666Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:14:38.263673Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13489689,
    events_root: None,
}
2023-02-06T02:14:38.263689Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:38.263692Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::London::0
2023-02-06T02:14:38.263693Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:38.263695Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:38.264254Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:14:38.264261Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14408087,
    events_root: None,
}
2023-02-06T02:14:38.264278Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:38.264280Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Merge::0
2023-02-06T02:14:38.264282Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:38.264284Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:38.264869Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:14:38.264876Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14925859,
    events_root: None,
}
2023-02-06T02:14:38.265714Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:14:38.265737Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:14:38.290473Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:38.290575Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:38.290578Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:38.290631Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:38.290705Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:38.290708Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Istanbul::0
2023-02-06T02:14:38.290711Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:14:38.290713Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:14:38.895046Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:14:38.895058Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13659830,
    events_root: None,
}
2023-02-06T02:14:38.895082Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:38.895086Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Berlin::0
2023-02-06T02:14:38.895088Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:14:38.895089Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:14:38.895674Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:14:38.895682Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12559237,
    events_root: None,
}
2023-02-06T02:14:38.895693Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:38.895695Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::London::0
2023-02-06T02:14:38.895697Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:14:38.895699Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:14:38.896232Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:14:38.896239Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13477452,
    events_root: None,
}
2023-02-06T02:14:38.896254Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:38.896256Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Merge::0
2023-02-06T02:14:38.896258Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:14:38.896260Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:14:38.896817Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:14:38.896824Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13995224,
    events_root: None,
}
2023-02-06T02:14:38.897671Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:14:38.897691Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:14:38.923184Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:38.923304Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:38.923309Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:38.923376Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:38.923478Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:38.923483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Istanbul::0
2023-02-06T02:14:38.923487Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:14:38.923491Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.276515Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:14:39.276536Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2509963,
    events_root: None,
}
2023-02-06T02:14:39.276545Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:39.276548Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Berlin::0
2023-02-06T02:14:39.276550Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:14:39.276552Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.276684Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:14:39.276691Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:14:39.276696Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:39.276698Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::London::0
2023-02-06T02:14:39.276700Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:14:39.276702Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.276798Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:14:39.276803Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:14:39.276808Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:39.276810Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Merge::0
2023-02-06T02:14:39.276811Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:14:39.276813Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.276908Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:14:39.276913Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:14:39.277583Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:14:39.277614Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:14:39.302538Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:39.302646Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:39.302649Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:39.302703Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:39.302775Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:39.302778Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Istanbul::0
2023-02-06T02:14:39.302782Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:14:39.302784Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.661208Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:14:39.661228Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8688838,
    events_root: None,
}
2023-02-06T02:14:39.661240Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:39.661244Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Berlin::0
2023-02-06T02:14:39.661245Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:14:39.661247Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.661341Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:14:39.661347Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:39.661351Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:39.661353Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::London::0
2023-02-06T02:14:39.661355Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:14:39.661356Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.661425Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:14:39.661429Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:39.661433Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:39.661435Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Merge::0
2023-02-06T02:14:39.661438Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:14:39.661439Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:39.661506Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:14:39.661511Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:39.662173Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:14:39.662202Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:14:39.686683Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:39.686789Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:39.686793Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:39.686847Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:39.686919Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:39.686922Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Istanbul::0
2023-02-06T02:14:39.686926Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:14:39.686928Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.032285Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:14:40.032306Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7674311,
    events_root: None,
}
2023-02-06T02:14:40.032318Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:40.032321Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Berlin::0
2023-02-06T02:14:40.032323Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:14:40.032325Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.032407Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:14:40.032413Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:40.032417Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:40.032419Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::London::0
2023-02-06T02:14:40.032420Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:14:40.032423Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.032503Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:14:40.032510Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:40.032515Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:40.032518Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Merge::0
2023-02-06T02:14:40.032520Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:14:40.032522Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.032610Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:14:40.032616Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:40.033360Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:14:40.033384Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:14:40.058496Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:40.058595Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.058598Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:40.058642Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.058644Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:40.058701Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.058703Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-06T02:14:40.058755Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.058758Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-06T02:14:40.058808Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.058880Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:40.058884Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:14:40.058887Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.058889Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.423780Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.423798Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.423808Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:40.423811Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:14:40.423813Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.423815Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.423968Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.423974Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.423981Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:40.423983Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:14:40.423986Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.423988Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.424113Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.424119Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.424125Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:40.424127Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:14:40.424129Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.424130Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.424257Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.424262Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.424268Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:40.424270Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:14:40.424272Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.424274Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.424398Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.424404Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.424410Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:40.424412Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:14:40.424413Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:14:40.424415Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:40.424538Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:14:40.424544Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:14:40.425241Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:14:40.425287Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:14:40.451883Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:40.451983Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.451987Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:40.452039Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.452041Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:14:40.452098Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.452170Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:40.452173Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Istanbul::0
2023-02-06T02:14:40.452177Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:14:40.452179Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:14:40.814979Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:14:40.814996Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3615148,
    events_root: None,
}
2023-02-06T02:14:40.815006Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:40.815009Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Berlin::0
2023-02-06T02:14:40.815011Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:14:40.815012Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:14:40.815099Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:14:40.815104Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:14:40.815108Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:40.815110Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::London::0
2023-02-06T02:14:40.815112Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:14:40.815114Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:14:40.815179Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:14:40.815183Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:14:40.815187Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:40.815189Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Merge::0
2023-02-06T02:14:40.815190Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:14:40.815192Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:14:40.815255Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:14:40.815260Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:14:40.815940Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:14:40.815966Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:14:40.840072Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:40.840170Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.840173Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:40.840224Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:40.840294Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:40.840297Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Istanbul::0
2023-02-06T02:14:40.840299Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:14:40.840301Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.197425Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:14:41.197441Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:14:41.197450Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:41.197454Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Berlin::0
2023-02-06T02:14:41.197455Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:14:41.197457Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.197560Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:14:41.197566Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:14:41.197571Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:41.197573Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::London::0
2023-02-06T02:14:41.197575Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:14:41.197576Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.197657Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:14:41.197662Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:14:41.197666Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:41.197668Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Merge::0
2023-02-06T02:14:41.197669Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:14:41.197671Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.197751Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:14:41.197755Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:14:41.198382Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:14:41.198405Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:14:41.223166Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:41.223262Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:41.223266Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:41.223316Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:41.223386Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:41.223389Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Istanbul::0
2023-02-06T02:14:41.223391Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:14:41.223393Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.592029Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:14:41.592050Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:14:41.592060Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:41.592063Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Berlin::0
2023-02-06T02:14:41.592065Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:14:41.592066Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.592170Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:14:41.592176Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:14:41.592181Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:41.592183Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::London::0
2023-02-06T02:14:41.592184Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:14:41.592186Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.592273Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:14:41.592278Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:14:41.592283Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:41.592284Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Merge::0
2023-02-06T02:14:41.592287Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:14:41.592288Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.592373Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:14:41.592378Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:14:41.592982Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:14:41.593009Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:14:41.617711Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:41.617812Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:41.617815Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:41.617867Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:41.617939Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:41.617942Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Istanbul::0
2023-02-06T02:14:41.617945Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:14:41.617947Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.978164Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:14:41.978186Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:14:41.978200Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:41.978204Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Berlin::0
2023-02-06T02:14:41.978206Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:14:41.978208Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.978348Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:14:41.978355Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:14:41.978363Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:41.978366Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::London::0
2023-02-06T02:14:41.978368Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:14:41.978370Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.978472Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:14:41.978478Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:14:41.978487Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:41.978489Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Merge::0
2023-02-06T02:14:41.978492Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:14:41.978494Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:41.978584Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:14:41.978590Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:14:41.979396Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:14:41.979422Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:14:42.004251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:42.004354Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.004357Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:42.004410Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.004481Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:42.004484Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Istanbul::0
2023-02-06T02:14:42.004487Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:14:42.004490Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.361502Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:14:42.361521Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746611,
    events_root: None,
}
2023-02-06T02:14:42.361531Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:42.361535Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Berlin::0
2023-02-06T02:14:42.361537Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:14:42.361538Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.361628Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:14:42.361633Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.361637Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:42.361639Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::London::0
2023-02-06T02:14:42.361641Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:14:42.361643Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.361711Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:14:42.361716Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.361720Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:42.361722Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Merge::0
2023-02-06T02:14:42.361723Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:14:42.361725Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.361791Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:14:42.361796Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.362576Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:14:42.362602Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:14:42.387564Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:42.387669Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.387672Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:42.387726Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.387800Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:42.387802Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Istanbul::0
2023-02-06T02:14:42.387805Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:14:42.387807Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.752093Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:14:42.752112Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2743390,
    events_root: None,
}
2023-02-06T02:14:42.752123Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:42.752126Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Berlin::0
2023-02-06T02:14:42.752127Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:14:42.752129Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.752217Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:14:42.752223Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.752227Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:42.752229Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::London::0
2023-02-06T02:14:42.752231Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:14:42.752233Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.752300Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:14:42.752305Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.752310Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:42.752311Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Merge::0
2023-02-06T02:14:42.752313Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:14:42.752315Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:42.752381Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:14:42.752386Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:42.753064Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:14:42.753090Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:42.777737Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:42.777839Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.777843Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:42.777896Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:42.777969Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:42.777972Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Istanbul::0
2023-02-06T02:14:42.777975Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:42.777977Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.166934Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:14:43.166954Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753817,
    events_root: None,
}
2023-02-06T02:14:43.166965Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:43.166969Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Berlin::0
2023-02-06T02:14:43.166971Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:43.166973Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.167059Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:14:43.167065Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.167069Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:43.167071Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::London::0
2023-02-06T02:14:43.167073Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:43.167075Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.167143Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:14:43.167148Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.167152Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:43.167154Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Merge::0
2023-02-06T02:14:43.167156Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:43.167157Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.167226Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:14:43.167231Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.167949Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:14:43.167971Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.193655Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:43.193755Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.193759Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:43.193815Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.193890Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:43.193893Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Istanbul::0
2023-02-06T02:14:43.193897Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.193899Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.562695Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:14:43.562711Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961071,
    events_root: None,
}
2023-02-06T02:14:43.562722Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:43.562725Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Berlin::0
2023-02-06T02:14:43.562727Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.562729Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.562822Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:14:43.562829Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.562833Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:43.562835Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::London::0
2023-02-06T02:14:43.562838Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.562839Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.562910Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:14:43.562916Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.562921Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:43.562923Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Merge::0
2023-02-06T02:14:43.562924Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.562926Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.562995Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:14:43.563000Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.563748Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:14:43.563780Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:14:43.589029Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:43.589131Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.589134Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:43.589189Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.589263Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:43.589266Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Istanbul::0
2023-02-06T02:14:43.589274Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:14:43.589278Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.935822Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:14:43.935845Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-02-06T02:14:43.935856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:43.935860Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Berlin::0
2023-02-06T02:14:43.935862Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:14:43.935865Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.935997Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:14:43.936005Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.936010Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:43.936012Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::London::0
2023-02-06T02:14:43.936014Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:14:43.936017Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.936104Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:14:43.936110Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.936115Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:43.936118Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Merge::0
2023-02-06T02:14:43.936120Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:14:43.936123Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:43.936212Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:14:43.936221Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:43.937139Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:14:43.937163Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:14:43.962642Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:43.962744Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.962747Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:43.962801Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:43.962874Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:43.962877Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Istanbul::0
2023-02-06T02:14:43.962880Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:14:43.962882Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:44.312394Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:14:44.312416Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773962,
    events_root: None,
}
2023-02-06T02:14:44.312428Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:44.312432Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Berlin::0
2023-02-06T02:14:44.312434Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:14:44.312436Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:44.312531Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:14:44.312538Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:44.312544Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:44.312547Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::London::0
2023-02-06T02:14:44.312549Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:14:44.312551Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:44.312636Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:14:44.312643Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:44.312649Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:44.312651Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Merge::0
2023-02-06T02:14:44.312653Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:14:44.312655Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:44.312751Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:14:44.312758Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:44.313855Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:14:44.313892Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.339028Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:44.339130Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:44.339134Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:44.339187Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:44.339260Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:44.339262Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Istanbul::0
2023-02-06T02:14:44.339265Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.339268Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:14:44.719223Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:14:44.719241Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000de0b6b3a7640000 },
    gas_used: 4955857,
    events_root: None,
}
2023-02-06T02:14:44.719255Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:44.719258Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Berlin::0
2023-02-06T02:14:44.719260Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.719262Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:14:44.719349Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:14:44.719355Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:14:44.719359Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:44.719361Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::London::0
2023-02-06T02:14:44.719362Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.719364Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:14:44.719434Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:14:44.719439Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:14:44.719443Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:44.719444Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Merge::0
2023-02-06T02:14:44.719446Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.719448Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:14:44.719516Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:14:44.719521Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:14:44.720154Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:14:44.720180Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:14:44.745026Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:44.745130Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:44.745133Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:44.745186Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:44.745258Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:44.745261Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Istanbul::0
2023-02-06T02:14:44.745264Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:14:44.745266Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:45.122751Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:14:45.122770Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2339024,
    events_root: None,
}
2023-02-06T02:14:45.122780Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:45.122783Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Berlin::0
2023-02-06T02:14:45.122785Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:14:45.122786Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:45.122874Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:14:45.122880Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:45.122884Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:45.122886Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::London::0
2023-02-06T02:14:45.122888Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:14:45.122890Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:45.122961Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:14:45.122966Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:45.122970Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:45.122972Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Merge::0
2023-02-06T02:14:45.122974Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:14:45.122975Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:14:45.123043Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:14:45.123047Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:14:45.123766Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:14:45.123787Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:14:45.149129Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:14:45.149229Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:45.149232Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:14:45.149293Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:14:45.149367Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:14:45.149370Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Istanbul::0
2023-02-06T02:14:45.149373Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:14:45.149374Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 136, 95, 13, 181, 217, 120, 204, 197, 243, 155, 145, 50, 151, 43, 92, 167, 175, 132, 25]) }
2023-02-06T02:14:45.818625Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:14:45.818639Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25501864,
    events_root: None,
}
2023-02-06T02:14:45.818670Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:14:45.818673Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Berlin::0
2023-02-06T02:14:45.818676Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:14:45.818677Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([239, 242, 33, 137, 111, 16, 15, 190, 235, 110, 77, 4, 63, 5, 41, 98, 192, 28, 206, 35]) }
2023-02-06T02:14:45.819687Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:14:45.819694Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25494214,
    events_root: None,
}
2023-02-06T02:14:45.819719Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:14:45.819721Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::London::0
2023-02-06T02:14:45.819722Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:14:45.819724Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [150, 151, 1, 50, 14, 235, 234, 97, 11, 211, 47, 136, 169, 204, 9, 15, 76, 88, 177, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [175, 233, 83, 17, 74, 10, 5, 74, 134, 230, 192, 174, 6, 155, 136, 139, 118, 51, 127, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 24, 246, 14, 245, 153, 41, 227, 62, 255, 40, 203, 90, 71, 156, 92, 203, 241, 198, 169]) }
2023-02-06T02:14:45.820708Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:14:45.820715Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25635545,
    events_root: None,
}
2023-02-06T02:14:45.820740Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:14:45.820742Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Merge::0
2023-02-06T02:14:45.820744Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:14:45.820746Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [164, 159, 137, 55, 107, 23, 23, 172, 189, 110, 149, 242, 218, 194, 80, 151, 112, 7, 220, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 136, 160, 236, 60, 241, 52, 128, 198, 110, 1, 228, 88, 211, 42, 243, 36, 124, 156, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([217, 138, 9, 115, 71, 212, 34, 51, 81, 252, 105, 199, 181, 39, 187, 149, 48, 141, 211, 216]) }
2023-02-06T02:14:45.821762Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:14:45.821768Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25899689,
    events_root: None,
}
2023-02-06T02:14:45.822736Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:14:45.823360Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 67 Files in Time:29.682805038s
=== Start ===
=== OK Status ===
Count :: 55
{
    "suicideCallerAddresTooBigLeft.json::suicideCallerAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb0.json::CallRecursiveBomb0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistrator0.json::CallToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CreateHashCollision.json::CreateHashCollision": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "callValue.json::callValue": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcalls2.json::ABAcalls2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb3.json::CallRecursiveBomb3": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "extcodecopy.json::extcodecopy": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "return1.json::return1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorZeorSizeMemExpansion.json::CallToNameRegistratorZeorSizeMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb2.json::CallRecursiveBomb2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideCaller.json::suicideCaller": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "testRandomTest.json::testRandomTest": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CalltoReturn2.json::CalltoReturn2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistrator.json::createNameRegistrator": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorAddressTooBigLeft.json::CallToNameRegistratorAddressTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcalls1.json::ABAcalls1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "currentAccountBalance.json::currentAccountBalance": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideAddress.json::suicideAddress": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "doubleSelfdestructTouch.json::doubleSelfdestructTouch": [
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcalls3.json::ABAcalls3": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "callerAccountBalance.json::callerAccountBalance": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorOutOfGas.json::CallToNameRegistratorOutOfGas": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorNotMuchMemory1.json::CallToNameRegistratorNotMuchMemory1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "balanceInputAddressTooBig.json::balanceInputAddressTooBig": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcallsSuicide0.json::ABAcallsSuicide0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideCallerAddresTooBigRight.json::suicideCallerAddresTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideOrigin.json::suicideOrigin": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "doubleSelfdestructTest.json::doubleSelfdestructTest": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorNotMuchMemory0.json::CallToNameRegistratorNotMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcallsSuicide1.json::ABAcallsSuicide1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 1 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 1 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 1 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 1 | ExitCode { value: 0 }",
    ],
    "return2.json::return2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "Call10.json::Call10": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorTooMuchMemory2.json::CallToNameRegistratorTooMuchMemory2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistratorValueTooHigh.json::createNameRegistratorValueTooHigh": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb1.json::CallRecursiveBomb1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorTooMuchMemory1.json::CallToNameRegistratorTooMuchMemory1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "return0.json::return0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideNotExistingAccount.json::suicideNotExistingAccount": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToReturn1.json::CallToReturn1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideSendEtherPostDeath.json::suicideSendEtherPostDeath": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistratorOOG_MemExpansionOOV.json::createNameRegistratorOOG_MemExpansionOOV": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistratorZeroMemExpansion.json::createNameRegistratorZeroMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcalls0.json::ABAcalls0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBombLog.json::CallRecursiveBombLog": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "TestNameRegistrator.json::TestNameRegistrator": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistratorZeroMem.json::createNameRegistratorZeroMem": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "PostToReturn1.json::PostToReturn1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createWithInvalidOpcode.json::createWithInvalidOpcode": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "suicideSendEtherToMe.json::suicideSendEtherToMe": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorAddressTooBigRight.json::CallToNameRegistratorAddressTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBombLog2.json::CallRecursiveBombLog2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "createNameRegistratorZeroMem2.json::createNameRegistratorZeroMem2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "doubleSelfdestructTest2.json::doubleSelfdestructTest2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
Count :: 13
{
    "callcodeToNameRegistratorAddresTooBigLeft.json::callcodeToNameRegistratorAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "callcodeToNameRegistratorAddresTooBigRight.json::callcodeToNameRegistratorAddresTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallToNameRegistratorTooMuchMemory0.json::CallToNameRegistratorTooMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 4 }",
        "Berlin | 0 | ExitCode { value: 4 }",
        "London | 0 | ExitCode { value: 4 }",
        "Merge | 0 | ExitCode { value: 4 }",
    ],
    "callcodeToReturn1.json::callcodeToReturn1": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "callcodeTo0.json::callcodeTo0": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallToNameRegistratorMemOOGAndInsufficientBalance.json::CallToNameRegistratorMemOOGAndInsufficientBalance": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "createNameRegistratorOutOfMemoryBonds0.json::createNameRegistratorOutOfMemoryBonds0": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "callcodeToNameRegistrator0.json::callcodeToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "callcodeToNameRegistratorZeroMemExpanion.json::callcodeToNameRegistratorZeroMemExpanion": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallToReturn1ForDynamicJump0.json::CallToReturn1ForDynamicJump0": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
    "CallToReturn1ForDynamicJump1.json::CallToReturn1ForDynamicJump1": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
    "createNameRegistratorOutOfMemoryBonds1.json::createNameRegistratorOutOfMemoryBonds1": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
}
=== SKIP Status ===
None
=== End ===
```