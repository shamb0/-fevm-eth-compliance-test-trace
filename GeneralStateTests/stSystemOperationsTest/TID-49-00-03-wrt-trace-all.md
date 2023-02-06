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

* Following use-cases are failed, when executed with test vector `transaction.gasLimit` x 20.

- Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| | CallRecursiveBomb0_OOG_atMaxCallDepth |
| | createNameRegistratorOutOfMemoryBonds1 |
| | CallToNameRegistratorMemOOGAndInsufficientBalance |
| | CallRecursiveBomb0_OOG_atMaxCallDepth |
| | createNameRegistratorOutOfMemoryBonds0 |


- Hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION`, ExitCode::35

| Test ID | Use-Case |
| --- | --- |
| | callcodeToNameRegistrator0 |
| | callcodeToNameRegistratorAddresTooBigRight |
| | callcodeTo0 |
| | callcodeToNameRegistratorAddresTooBigLeft |
| | callcodeToReturn1 |

- Hit with `EVM_CONTRACT_BAD_JUMPDEST`, ExitCode::39

| Test ID | Use-Case |
| --- | --- |
| | CallToReturn1ForDynamicJump0 |
| | CallToReturn1ForDynamicJump1 |

- Hit with error `SYS_OUT_OF_GAS`, (ExitCode::7)

| Test ID | Use-Case |
| --- | --- |
| | callcodeToNameRegistratorZeroMemExpanion |
| | testRandomTest |
| | createNameRegistratorZeroMemExpansion |
| | createNameRegistratorZeroMem |
| | CallToNameRegistratorZeorSizeMemExpansion |
| | createNameRegistratorZeroMem2 |
| | CallRecursiveBomb3 |
| | CallToNameRegistratorTooMuchMemory0 |
| | CallToNameRegistratorTooMuchMemory1 |
| | createNameRegistrator |
| | createWithInvalidOpcode |

> Execution Trace

```
2023-02-06T02:11:36.227704Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stSystemOperationsTest", Total Files :: 67
2023-02-06T02:11:36.227953Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:11:36.257567Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:36.257708Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.257712Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:36.257768Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.257771Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:36.257834Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.257910Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:36.257913Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Istanbul::0
2023-02-06T02:11:36.257917Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:11:36.257920Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:36.617437Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:11:36.617457Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:11:36.617468Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:36.617471Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Berlin::0
2023-02-06T02:11:36.617473Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:11:36.617475Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:36.617600Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:11:36.617607Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:11:36.617612Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:36.617614Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::London::0
2023-02-06T02:11:36.617616Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:11:36.617618Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:36.617731Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:11:36.617737Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:11:36.617743Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:36.617745Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Merge::0
2023-02-06T02:11:36.617747Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:11:36.617748Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:36.617878Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:11:36.617884Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:11:36.619219Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:11:36.619248Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:11:36.646291Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:36.646402Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.646406Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:36.646462Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.646465Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:36.646525Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:36.646599Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:36.646603Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Istanbul::0
2023-02-06T02:11:36.646607Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:11:36.646609Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.035514Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:11:37.035534Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 693181754,
    events_root: None,
}
2023-02-06T02:11:37.036889Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:37.036895Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Berlin::0
2023-02-06T02:11:37.036898Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:11:37.036900Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.069726Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:11:37.069763Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 553031705,
    events_root: None,
}
2023-02-06T02:11:37.070801Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:37.070807Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::London::0
2023-02-06T02:11:37.070809Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:11:37.070812Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.104628Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:11:37.104662Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 553031705,
    events_root: None,
}
2023-02-06T02:11:37.105740Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:37.105746Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Merge::0
2023-02-06T02:11:37.105748Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:11:37.105751Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.140800Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:11:37.140836Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 553031705,
    events_root: None,
}
2023-02-06T02:11:37.147421Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:11:37.147473Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:11:37.172738Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:37.172841Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.172844Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:37.172894Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.172896Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:37.172952Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.173022Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:37.173025Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Istanbul::0
2023-02-06T02:11:37.173027Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:11:37.173029Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.556119Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:11:37.556142Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 976589094,
    events_root: None,
}
2023-02-06T02:11:37.557820Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:37.557828Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Berlin::0
2023-02-06T02:11:37.557830Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:11:37.557832Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.599972Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:11:37.599991Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 976272436,
    events_root: None,
}
2023-02-06T02:11:37.601576Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:37.601582Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::London::0
2023-02-06T02:11:37.601584Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:11:37.601586Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.642237Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:11:37.642257Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 974998657,
    events_root: None,
}
2023-02-06T02:11:37.643794Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:37.643799Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Merge::0
2023-02-06T02:11:37.643801Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:11:37.643803Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:37.684561Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:11:37.684579Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 974998473,
    events_root: None,
}
2023-02-06T02:11:37.691109Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:11:37.691146Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:11:37.715854Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:37.715957Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.715960Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:37.716011Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.716013Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:37.716070Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:37.716139Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:37.716142Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Istanbul::0
2023-02-06T02:11:37.716145Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:11:37.716147Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.089593Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:11:38.089610Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 178729690,
    events_root: None,
}
2023-02-06T02:11:38.089830Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:38.089834Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Berlin::0
2023-02-06T02:11:38.089836Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:11:38.089838Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.097078Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:11:38.097090Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 178754204,
    events_root: None,
}
2023-02-06T02:11:38.097323Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:38.097326Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::London::0
2023-02-06T02:11:38.097328Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:11:38.097330Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.105697Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:11:38.105715Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 178754204,
    events_root: None,
}
2023-02-06T02:11:38.105962Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:38.105966Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Merge::0
2023-02-06T02:11:38.105968Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:11:38.105971Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.113785Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:11:38.113804Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 178754204,
    events_root: None,
}
2023-02-06T02:11:38.116484Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:11:38.116523Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:11:38.141779Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:38.141886Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.141890Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:38.141942Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.141944Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:38.141999Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.142071Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:38.142074Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Istanbul::0
2023-02-06T02:11:38.142077Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:11:38.142079Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.489607Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:11:38.489627Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631129,
    events_root: None,
}
2023-02-06T02:11:38.489636Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:38.489639Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Berlin::0
2023-02-06T02:11:38.489641Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:11:38.489643Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.489753Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:11:38.489759Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:38.489763Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:38.489765Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::London::0
2023-02-06T02:11:38.489767Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:11:38.489768Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.489836Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:11:38.489841Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:38.489845Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:38.489847Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Merge::0
2023-02-06T02:11:38.489849Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:11:38.489851Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:38.489918Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:11:38.489922Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:38.491513Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:11:38.491534Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:11:38.519265Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:38.519370Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.519374Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:38.519426Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.519429Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:38.519485Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.519563Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:38.519568Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::0
2023-02-06T02:11:38.519572Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.519574Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.903429Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.903449Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:11:38.903459Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 1
2023-02-06T02:11:38.903462Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::1
2023-02-06T02:11:38.903464Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.903466Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.903616Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.903622Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:11:38.903628Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:38.903630Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::0
2023-02-06T02:11:38.903632Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.903633Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.903750Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.903756Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:11:38.903762Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 1
2023-02-06T02:11:38.903764Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::1
2023-02-06T02:11:38.903766Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.903767Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.903912Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.903917Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:11:38.903923Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:38.903925Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::0
2023-02-06T02:11:38.903927Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.903929Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.904042Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.904048Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:11:38.904053Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 1
2023-02-06T02:11:38.904055Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::1
2023-02-06T02:11:38.904057Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.904059Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.904173Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.904178Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:11:38.904183Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:38.904186Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::0
2023-02-06T02:11:38.904187Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.904189Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.904302Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.904308Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:11:38.904313Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 1
2023-02-06T02:11:38.904315Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::1
2023-02-06T02:11:38.904317Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:11:38.904318Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:11:38.904462Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:11:38.904469Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:11:38.906033Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:11:38.906058Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:11:38.932716Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:38.932826Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.932829Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:38.932878Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.932880Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:38.932935Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:38.933008Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:38.933011Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Istanbul::0
2023-02-06T02:11:38.933014Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:11:38.933016Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.281186Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:11:39.281205Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25719303,
    events_root: None,
}
2023-02-06T02:11:39.281243Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:39.281247Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Berlin::0
2023-02-06T02:11:39.281249Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:11:39.281250Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.282594Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:11:39.282601Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:11:39.282635Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:39.282637Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::London::0
2023-02-06T02:11:39.282638Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:11:39.282640Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.283984Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:11:39.283990Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:11:39.284023Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:39.284025Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Merge::0
2023-02-06T02:11:39.284027Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:11:39.284028Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.285380Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:11:39.285386Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:11:39.286492Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:11:39.286525Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:11:39.311244Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:39.311354Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:39.311358Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:39.311410Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:39.311412Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:39.311469Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:39.311557Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:39.311563Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Istanbul::0
2023-02-06T02:11:39.311566Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:11:39.311569Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.677594Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:11:39.677613Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:39.677725Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:39.677729Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Berlin::0
2023-02-06T02:11:39.677731Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:11:39.677732Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.681607Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:11:39.681614Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:39.681727Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:39.681730Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::London::0
2023-02-06T02:11:39.681731Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:11:39.681733Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.685629Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:11:39.685636Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:39.685750Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:39.685752Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Merge::0
2023-02-06T02:11:39.685754Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:11:39.685756Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:39.690118Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:11:39.690127Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:39.692284Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:11:39.692310Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:39.717610Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:39.717710Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:39.717713Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:39.717763Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:39.717832Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:39.717835Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Istanbul::0
2023-02-06T02:11:39.717838Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:39.717840Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.186101Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:11:40.186119Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2052114286,
    events_root: None,
}
2023-02-06T02:11:40.188977Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:40.188985Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Berlin::0
2023-02-06T02:11:40.188988Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:40.188990Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.270633Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:11:40.270653Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1989739681,
    events_root: None,
}
2023-02-06T02:11:40.272926Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:40.272934Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::London::0
2023-02-06T02:11:40.272936Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:40.272939Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.274202Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:11:40.274212Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2293561,
    events_root: None,
}
2023-02-06T02:11:40.274216Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:40.274229Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:40.274231Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Merge::0
2023-02-06T02:11:40.274233Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:40.274235Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.274365Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:11:40.274371Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2293561,
    events_root: None,
}
2023-02-06T02:11:40.274374Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:40.281667Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:11:40.281701Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:11:40.304895Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:40.304993Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:40.304997Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:40.305047Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:40.305117Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:40.305120Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Istanbul::0
2023-02-06T02:11:40.305123Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:11:40.305125Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.703623Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:11:40.703643Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 302937953,
    events_root: None,
}
2023-02-06T02:11:40.704043Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:40.704048Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Berlin::0
2023-02-06T02:11:40.704050Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:11:40.704053Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.716444Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:11:40.716463Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762834,
    events_root: None,
}
2023-02-06T02:11:40.716903Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:40.716911Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::London::0
2023-02-06T02:11:40.716913Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:11:40.716916Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.729337Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:11:40.729354Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762834,
    events_root: None,
}
2023-02-06T02:11:40.729718Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:40.729723Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Merge::0
2023-02-06T02:11:40.729726Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:11:40.729728Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:40.742398Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:11:40.742417Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762834,
    events_root: None,
}
2023-02-06T02:11:40.744721Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:11:40.744751Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:11:40.768618Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:40.768724Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:40.768728Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:40.768781Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:40.768856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:40.768860Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Istanbul::0
2023-02-06T02:11:40.768864Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:11:40.768866Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.127999Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:11:41.128017Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 302937944,
    events_root: None,
}
2023-02-06T02:11:41.128394Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:41.128399Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Berlin::0
2023-02-06T02:11:41.128401Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:11:41.128404Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.141114Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:11:41.141133Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762820,
    events_root: None,
}
2023-02-06T02:11:41.141533Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:41.141538Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::London::0
2023-02-06T02:11:41.141540Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:11:41.141543Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.154476Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:11:41.154497Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762820,
    events_root: None,
}
2023-02-06T02:11:41.154923Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:41.154928Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Merge::0
2023-02-06T02:11:41.154931Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:11:41.154933Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.167917Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:11:41.167935Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 338762820,
    events_root: None,
}
2023-02-06T02:11:41.170210Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:11:41.170238Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:11:41.196573Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:41.196723Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:41.196736Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:41.196812Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:41.196914Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:41.196925Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Istanbul::0
2023-02-06T02:11:41.196933Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:11:41.196941Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.550719Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:11:41.550739Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20000000,
    events_root: None,
}
2023-02-06T02:11:41.550744Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:41.550802Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:41.550806Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Berlin::0
2023-02-06T02:11:41.550808Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:11:41.550811Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.551663Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:11:41.551671Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20000000,
    events_root: None,
}
2023-02-06T02:11:41.551675Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:41.551732Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:41.551735Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::London::0
2023-02-06T02:11:41.551738Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:11:41.551740Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.552603Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:11:41.552610Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20000000,
    events_root: None,
}
2023-02-06T02:11:41.552614Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:41.552669Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:41.552672Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Merge::0
2023-02-06T02:11:41.552674Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:11:41.552675Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.553497Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:11:41.553504Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20000000,
    events_root: None,
}
2023-02-06T02:11:41.553507Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:41.554381Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:11:41.554403Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:11:41.579026Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:41.579134Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:41.579138Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:41.579190Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:41.579193Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:41.579250Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:41.579324Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:41.579327Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Istanbul::0
2023-02-06T02:11:41.579330Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:11:41.579332Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.971696Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:11:41.971716Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:41.971837Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:41.971842Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Berlin::0
2023-02-06T02:11:41.971844Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:11:41.971846Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.976204Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:11:41.976216Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:41.976347Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:41.976351Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::London::0
2023-02-06T02:11:41.976353Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:11:41.976355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.980883Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:11:41.980894Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:41.981018Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:41.981022Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Merge::0
2023-02-06T02:11:41.981024Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:11:41.981025Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:41.985336Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:11:41.985344Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:41.986739Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:11:41.986765Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:11:42.010624Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:42.010729Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.010732Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:42.010782Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.010785Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:42.010841Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.010913Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:42.010916Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Istanbul::0
2023-02-06T02:11:42.010919Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:11:42.010921Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.372634Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:11:42.372654Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:42.372775Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:42.372779Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Berlin::0
2023-02-06T02:11:42.372781Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:11:42.372783Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.377042Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:11:42.377051Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:42.377184Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:42.377187Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::London::0
2023-02-06T02:11:42.377189Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:11:42.377192Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.381781Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:11:42.381795Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:42.381931Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:42.381934Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Merge::0
2023-02-06T02:11:42.381936Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:11:42.381938Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.386239Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:11:42.386247Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:11:42.387635Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:11:42.387660Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:11:42.411484Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:42.411585Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.411588Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:42.411638Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.411640Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:42.411696Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.411766Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:42.411768Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Istanbul::0
2023-02-06T02:11:42.411771Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:11:42.411773Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.757682Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:11:42.757699Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:11:42.757709Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:42.757712Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Berlin::0
2023-02-06T02:11:42.757714Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:11:42.757716Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.757891Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:11:42.757898Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:11:42.757904Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:42.757907Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::London::0
2023-02-06T02:11:42.757908Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:11:42.757910Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.758025Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:11:42.758031Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:11:42.758036Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:42.758039Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Merge::0
2023-02-06T02:11:42.758040Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:11:42.758042Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:42.758179Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:11:42.758186Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:11:42.758863Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:11:42.758896Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:42.783522Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:42.783633Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.783637Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:42.783703Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.783706Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:42.783777Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:42.783856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:42.783860Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Istanbul::0
2023-02-06T02:11:42.783863Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:42.783865Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.130033Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:11:43.130056Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:11:43.130065Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:43.130068Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Berlin::0
2023-02-06T02:11:43.130070Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:43.130072Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.130201Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:11:43.130208Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:11:43.130213Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:43.130216Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::London::0
2023-02-06T02:11:43.130219Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:43.130221Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.130335Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:11:43.130342Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:11:43.130347Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:43.130349Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Merge::0
2023-02-06T02:11:43.130351Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:43.130353Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.130465Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:11:43.130471Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:11:43.131092Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:11:43.131125Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.155562Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:43.155661Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.155664Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:43.155715Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.155717Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:43.155774Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.155851Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:43.155854Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Istanbul::0
2023-02-06T02:11:43.155857Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.155859Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.550929Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:11:43.550950Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006546,
    events_root: None,
}
2023-02-06T02:11:43.550959Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:43.550963Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Berlin::0
2023-02-06T02:11:43.550964Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.550966Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.551103Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:11:43.551110Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:11:43.551115Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:43.551117Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::London::0
2023-02-06T02:11:43.551119Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.551120Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.551239Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:11:43.551246Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:11:43.551254Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:43.551257Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Merge::0
2023-02-06T02:11:43.551260Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.551262Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.551396Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:11:43.551403Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-02-06T02:11:43.552246Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:11:43.552274Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.577445Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:43.577568Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.577573Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:43.577628Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.577630Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:43.577688Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.577765Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:43.577769Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Istanbul::0
2023-02-06T02:11:43.577772Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.577775Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.943289Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:11:43.943308Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:11:43.943313Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:43.943327Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:43.943330Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Berlin::0
2023-02-06T02:11:43.943332Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.943337Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.943468Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:11:43.943474Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:11:43.943477Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:43.943486Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:43.943487Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::London::0
2023-02-06T02:11:43.943490Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.943492Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.943584Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:11:43.943590Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:11:43.943593Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:43.943601Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:43.943603Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Merge::0
2023-02-06T02:11:43.943605Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.943607Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:43.943697Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:11:43.943703Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:11:43.943706Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:43.944321Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:11:43.944341Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:43.968756Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:43.968858Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.968861Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:43.968912Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.968914Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:43.968971Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:43.969042Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:43.969045Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Istanbul::0
2023-02-06T02:11:43.969048Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:43.969050Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.310657Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:11:44.310678Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:11:44.310688Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:44.310691Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Berlin::0
2023-02-06T02:11:44.310693Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:44.310695Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.310819Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:11:44.310825Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:11:44.310831Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:44.310833Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::London::0
2023-02-06T02:11:44.310835Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:44.310837Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.310964Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:11:44.310970Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:11:44.310976Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:44.310978Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Merge::0
2023-02-06T02:11:44.310980Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:44.310982Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.311095Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:11:44.311102Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:11:44.311747Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:11:44.311774Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.335673Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:44.335776Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.335780Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:44.335831Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.335834Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:44.335891Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.335962Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:44.335965Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Istanbul::0
2023-02-06T02:11:44.335969Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.335971Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.679305Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:11:44.679326Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:11:44.679337Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:44.679341Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Berlin::0
2023-02-06T02:11:44.679343Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.679346Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.679485Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:11:44.679492Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:11:44.679498Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:44.679501Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::London::0
2023-02-06T02:11:44.679504Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.679507Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.679619Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:11:44.679626Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:11:44.679632Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:44.679635Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Merge::0
2023-02-06T02:11:44.679638Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.679640Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:44.679751Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:11:44.679758Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:11:44.680427Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:11:44.680459Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:44.704093Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:44.704197Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.704201Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:44.704252Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.704255Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:44.704312Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:44.704383Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:44.704386Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Istanbul::0
2023-02-06T02:11:44.704389Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:44.704391Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.085566Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:11:45.085586Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:11:45.085597Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:45.085601Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Berlin::0
2023-02-06T02:11:45.085602Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:45.085605Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.085751Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:11:45.085757Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:11:45.085763Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:45.085765Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::London::0
2023-02-06T02:11:45.085767Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:45.085768Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.085898Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:11:45.085904Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:11:45.085910Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:45.085912Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Merge::0
2023-02-06T02:11:45.085914Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:45.085916Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.086026Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:11:45.086032Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:11:45.086756Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:11:45.086780Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.110629Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:45.110730Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.110733Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:45.110783Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.110785Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:45.110839Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.110910Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:45.110912Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Istanbul::0
2023-02-06T02:11:45.110915Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.110917Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.459756Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:11:45.459777Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.459782Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.459796Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:45.459799Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Berlin::0
2023-02-06T02:11:45.459801Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.459803Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.459919Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:11:45.459924Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.459927Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.459936Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:45.459937Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::London::0
2023-02-06T02:11:45.459939Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.459941Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.460026Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:11:45.460031Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.460034Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.460042Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:45.460044Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Merge::0
2023-02-06T02:11:45.460046Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.460048Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.460130Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:11:45.460135Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.460138Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.460801Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:11:45.460823Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.484500Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:45.484599Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.484602Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:45.484651Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.484653Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:45.484708Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.484777Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:45.484780Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Istanbul::0
2023-02-06T02:11:45.484783Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.484785Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.866417Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:11:45.866439Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.866444Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.866456Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:45.866459Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Berlin::0
2023-02-06T02:11:45.866461Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.866463Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.866589Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:11:45.866595Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.866598Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.866606Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:45.866608Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::London::0
2023-02-06T02:11:45.866610Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.866612Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.866707Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:11:45.866712Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.866715Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.866723Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:45.866725Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Merge::0
2023-02-06T02:11:45.866727Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.866729Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:45.866823Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:11:45.866828Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:45.866831Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:45.867458Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:11:45.867483Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:45.891452Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:45.891551Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.891554Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:45.891604Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.891606Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:45.891663Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:45.891733Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:45.891736Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Istanbul::0
2023-02-06T02:11:45.891740Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:45.891742Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.238063Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:11:46.238082Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:11:46.238092Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:46.238095Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Berlin::0
2023-02-06T02:11:46.238097Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:46.238099Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.238425Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:11:46.238431Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:11:46.238437Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:46.238439Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::London::0
2023-02-06T02:11:46.238441Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:46.238443Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.238735Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:11:46.238742Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:11:46.238747Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:46.238748Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Merge::0
2023-02-06T02:11:46.238751Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:46.238753Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.239087Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:11:46.239095Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:11:46.240212Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:11:46.240246Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.265669Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:46.265777Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.265781Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:46.265833Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.265835Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:46.265892Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.265964Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:46.265967Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:11:46.265970Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.265973Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.619527Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.619547Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:11:46.619558Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:46.619562Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:11:46.619564Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.619567Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.619666Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.619672Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:46.619676Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:46.619689Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:46.619692Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:11:46.619694Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.619697Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.619813Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.619821Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:11:46.619828Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:46.619831Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:11:46.619834Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.619837Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.619935Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.619941Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:46.619945Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:46.619955Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:46.619958Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:11:46.619961Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.619964Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.620074Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.620081Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:11:46.620088Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:46.620090Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:11:46.620093Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.620096Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.620173Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.620179Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:46.620183Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:46.620193Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:46.620196Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:11:46.620199Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.620201Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.620313Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.620319Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:11:46.620326Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:46.620329Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:11:46.620332Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.620335Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.620409Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:11:46.620415Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:46.620418Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:46.621050Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:11:46.621082Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:11:46.645681Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:46.645789Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.645792Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:46.645845Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.645847Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:46.645905Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:46.645978Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:46.645980Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Istanbul::0
2023-02-06T02:11:46.645983Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:11:46.645985Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.999560Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:11:46.999585Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:11:46.999596Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:46.999599Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Berlin::0
2023-02-06T02:11:46.999601Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:11:46.999603Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.999759Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:11:46.999765Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:11:46.999770Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:46.999772Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::London::0
2023-02-06T02:11:46.999774Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:11:46.999775Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:46.999887Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:11:46.999892Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:11:46.999898Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:46.999900Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Merge::0
2023-02-06T02:11:46.999903Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:11:46.999905Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.000013Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:11:47.000019Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:11:47.000776Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:11:47.000813Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.025309Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:47.025419Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.025423Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:47.025474Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.025478Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:47.025535Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.025610Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:47.025614Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Istanbul::0
2023-02-06T02:11:47.025617Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.025620Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.362135Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:11:47.362155Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:11:47.362160Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.362173Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:47.362176Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Berlin::0
2023-02-06T02:11:47.362178Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.362180Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.362333Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:11:47.362340Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:11:47.362343Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.362353Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:47.362356Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::London::0
2023-02-06T02:11:47.362358Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.362360Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.362478Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:11:47.362484Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:11:47.362487Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.362496Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:47.362498Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Merge::0
2023-02-06T02:11:47.362501Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.362503Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.362619Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:11:47.362625Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:11:47.362628Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.363319Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:11:47.363339Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.387331Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:47.387436Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.387440Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:47.387489Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.387491Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:47.387548Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.387618Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:47.387621Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Istanbul::0
2023-02-06T02:11:47.387624Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.387626Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.723147Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:11:47.723168Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:11:47.723173Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.723185Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:47.723189Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Berlin::0
2023-02-06T02:11:47.723190Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.723192Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.723317Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:11:47.723323Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:11:47.723326Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.723335Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:47.723337Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::London::0
2023-02-06T02:11:47.723339Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.723340Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.723451Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:11:47.723457Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:11:47.723459Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.723468Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:47.723470Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Merge::0
2023-02-06T02:11:47.723472Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.723475Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:47.723579Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:11:47.723584Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:11:47.723587Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:47.724223Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:11:47.724243Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:11:47.750229Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:47.750361Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.750366Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:47.750433Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.750437Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:47.750512Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:47.750616Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:47.750622Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Istanbul::0
2023-02-06T02:11:47.750626Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:11:47.750628Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:48.098854Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:11:48.098876Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:11:48.098887Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:48.098891Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Berlin::0
2023-02-06T02:11:48.098894Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:11:48.098896Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:48.099054Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:11:48.099061Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:11:48.099067Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:48.099070Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::London::0
2023-02-06T02:11:48.099073Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:11:48.099075Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:48.099190Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:11:48.099196Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:11:48.099203Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:48.099206Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Merge::0
2023-02-06T02:11:48.099208Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:11:48.099211Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:48.099354Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:11:48.099363Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:11:48.100350Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:11:48.100388Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:11:48.125423Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:48.125535Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.125539Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:48.125595Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.125597Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:48.125657Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.125733Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:48.125736Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Istanbul::0
2023-02-06T02:11:48.125741Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:11:48.125744Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:48.567531Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:11:48.567549Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3909237,
    events_root: None,
}
2023-02-06T02:11:48.567564Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:48.567567Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Berlin::0
2023-02-06T02:11:48.567569Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:11:48.567571Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:48.743650Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:11:48.743663Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13534900,
    events_root: None,
}
2023-02-06T02:11:48.743687Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:48.743690Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::London::0
2023-02-06T02:11:48.743692Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:11:48.743694Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:48.744327Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:11:48.744334Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-02-06T02:11:48.744350Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:48.744352Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Merge::0
2023-02-06T02:11:48.744354Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:11:48.744356Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:48.744939Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:11:48.744945Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-02-06T02:11:48.745859Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:11:48.745884Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:11:48.772532Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:48.772640Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.772644Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:48.772697Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.772699Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:48.772759Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:48.772832Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:48.772836Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Istanbul::0
2023-02-06T02:11:48.772839Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:11:48.772841Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.124285Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:11:49.124305Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2702051,
    events_root: None,
}
2023-02-06T02:11:49.124315Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:49.124318Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Berlin::0
2023-02-06T02:11:49.124320Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:11:49.124322Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.124472Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:11:49.124483Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:11:49.124490Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:49.124492Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::London::0
2023-02-06T02:11:49.124494Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:11:49.124496Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.124636Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:11:49.124643Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:11:49.124650Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:49.124652Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Merge::0
2023-02-06T02:11:49.124655Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:11:49.124658Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.124792Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:11:49.124798Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:11:49.125547Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:11:49.125571Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:11:49.150145Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:49.150255Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.150258Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:49.150314Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.150387Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:49.150390Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Istanbul::0
2023-02-06T02:11:49.150393Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:11:49.150395Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:11:49.543515Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:11:49.543536Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2563734,
    events_root: None,
}
2023-02-06T02:11:49.543546Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:49.543550Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Berlin::0
2023-02-06T02:11:49.543551Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:11:49.543553Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:11:49.543665Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:11:49.543671Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:11:49.543675Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:49.543677Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::London::0
2023-02-06T02:11:49.543679Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:11:49.543681Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:11:49.543770Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:11:49.543775Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:11:49.543780Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:49.543781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Merge::0
2023-02-06T02:11:49.543783Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:11:49.543785Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:11:49.543873Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:11:49.543879Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:11:49.544506Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:11:49.544536Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:11:49.568698Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:49.568804Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.568807Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:49.568859Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.568930Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:49.568933Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Istanbul::0
2023-02-06T02:11:49.568936Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:11:49.568939Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.971994Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:11:49.972015Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:11:49.972024Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:49.972028Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Berlin::0
2023-02-06T02:11:49.972030Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:11:49.972032Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.972160Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:11:49.972167Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:11:49.972172Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:49.972174Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::London::0
2023-02-06T02:11:49.972175Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:11:49.972177Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.972278Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:11:49.972284Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:11:49.972289Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:49.972291Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Merge::0
2023-02-06T02:11:49.972293Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:11:49.972295Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:49.972394Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:11:49.972400Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:11:49.972982Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:11:49.973009Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:11:49.996843Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:49.996946Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.996950Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:49.997002Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:49.997073Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:49.997076Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Istanbul::0
2023-02-06T02:11:49.997079Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:11:49.997081Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.371026Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:11:50.371045Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:11:50.371053Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:50.371057Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Berlin::0
2023-02-06T02:11:50.371059Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:11:50.371060Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.371159Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:11:50.371165Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:11:50.371169Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:50.371171Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::London::0
2023-02-06T02:11:50.371173Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:11:50.371175Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.371256Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:11:50.371261Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:11:50.371265Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:50.371267Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Merge::0
2023-02-06T02:11:50.371269Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:11:50.371270Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.371349Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:11:50.371354Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:11:50.371992Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:11:50.372019Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:11:50.395781Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:50.395949Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:50.395955Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:50.396057Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:50.396196Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:50.396201Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Istanbul::0
2023-02-06T02:11:50.396206Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:11:50.396209Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.743163Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:11:50.743183Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:11:50.743187Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:50.743202Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:50.743205Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Berlin::0
2023-02-06T02:11:50.743207Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:11:50.743209Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.743329Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:11:50.743334Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:11:50.743337Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:50.743346Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:50.743349Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::London::0
2023-02-06T02:11:50.743351Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:11:50.743353Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.743454Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:11:50.743460Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:11:50.743463Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:50.743472Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:50.743474Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Merge::0
2023-02-06T02:11:50.743476Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:11:50.743478Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:50.743564Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:11:50.743569Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:11:50.743571Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:50.744208Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:11:50.744233Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:11:50.768926Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:50.769033Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:50.769036Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:50.769087Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:50.769090Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:50.769149Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:50.769219Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:50.769222Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Istanbul::0
2023-02-06T02:11:50.769225Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:11:50.769227Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.152235Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:11:51.152260Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:51.152266Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.152283Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:51.152287Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Berlin::0
2023-02-06T02:11:51.152290Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:11:51.152293Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.152428Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:11:51.152435Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:51.152438Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.152451Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:51.152453Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::London::0
2023-02-06T02:11:51.152455Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:11:51.152458Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.152575Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:11:51.152582Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:51.152588Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.152599Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:51.152601Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Merge::0
2023-02-06T02:11:51.152604Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:11:51.152607Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.152720Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:11:51.152727Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:51.152730Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.153702Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:11:51.153732Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.179194Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:51.179297Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.179300Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:51.179352Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.179354Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:51.179410Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.179481Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:51.179484Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Istanbul::0
2023-02-06T02:11:51.179487Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.179489Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.560136Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:11:51.560156Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.560160Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.560173Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:51.560176Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Berlin::0
2023-02-06T02:11:51.560178Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.560180Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.560286Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:11:51.560291Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.560294Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.560303Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:51.560305Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::London::0
2023-02-06T02:11:51.560307Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.560309Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.560396Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:11:51.560402Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.560404Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.560413Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:51.560415Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Merge::0
2023-02-06T02:11:51.560417Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.560419Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.560504Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:11:51.560509Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.560512Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.561204Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:11:51.561230Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.585161Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:51.585262Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.585266Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:51.585323Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.585326Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:51.585382Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.585453Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:51.585455Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Istanbul::0
2023-02-06T02:11:51.585459Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.585461Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.938188Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:11:51.938208Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.938213Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.938228Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:51.938232Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Berlin::0
2023-02-06T02:11:51.938235Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.938237Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.938374Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:11:51.938381Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.938385Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.938397Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:51.938399Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::London::0
2023-02-06T02:11:51.938402Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.938405Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.938502Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:11:51.938508Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.938512Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.938523Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:51.938526Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Merge::0
2023-02-06T02:11:51.938528Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.938531Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:51.938626Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:11:51.938633Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:11:51.938636Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:51.939257Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:11:51.939281Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:51.963718Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:51.963823Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.963827Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:51.963881Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.963884Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:51.963951Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:51.964025Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:51.964029Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:11:51.964033Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:51.964035Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.322478Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.322498Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:52.322503Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:52.322515Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:52.322518Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:11:52.322521Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.322523Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.322657Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.322664Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.322666Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.322675Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:52.322677Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:11:52.322679Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.322681Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.322752Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.322758Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:52.322760Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:52.322768Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:52.322770Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:11:52.322772Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.322774Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.322863Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.322868Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.322871Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.322879Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:52.322881Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:11:52.322883Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.322885Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.322954Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.322961Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:52.322966Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:52.322973Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:52.322975Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:11:52.322977Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.322980Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.323067Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.323073Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.323076Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.323085Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:52.323087Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:11:52.323089Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.323091Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.323159Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.323164Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T02:11:52.323166Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:52.323174Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:52.323175Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:11:52.323177Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.323179Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.323266Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:11:52.323272Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.323275Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.323900Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:11:52.323921Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:11:52.347753Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:52.347853Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:52.347856Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:52.347906Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:52.347908Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:52.347964Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:52.348036Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:52.348039Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Istanbul::0
2023-02-06T02:11:52.348042Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:11:52.348044Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.690178Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:11:52.690198Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.690203Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.690216Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:52.690220Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Berlin::0
2023-02-06T02:11:52.690221Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:11:52.690223Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.690347Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:11:52.690353Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.690357Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.690366Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:52.690368Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::London::0
2023-02-06T02:11:52.690369Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:11:52.690371Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.690462Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:11:52.690467Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.690470Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.690479Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:52.690481Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Merge::0
2023-02-06T02:11:52.690483Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:11:52.690484Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:52.690572Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:11:52.690578Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:11:52.690580Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:52.691379Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:11:52.691403Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:11:52.717263Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:52.717376Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:52.717379Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:52.717432Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:52.717504Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:52.717507Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Istanbul::0
2023-02-06T02:11:52.717510Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:11:52.717512Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:53.062021Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:11:53.062046Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2479617,
    events_root: None,
}
2023-02-06T02:11:53.062056Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:53.062061Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Berlin::0
2023-02-06T02:11:53.062063Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:11:53.062065Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:53.062238Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:11:53.062245Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:11:53.062250Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:53.062252Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::London::0
2023-02-06T02:11:53.062254Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:11:53.062256Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:53.062353Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:11:53.062358Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:11:53.062362Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:53.062364Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Merge::0
2023-02-06T02:11:53.062366Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:11:53.062368Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:53.062458Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:11:53.062463Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:11:53.063200Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:11:53.063228Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:11:53.088272Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:53.088379Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:53.088382Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:53.088438Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:53.088510Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:53.088513Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Istanbul::0
2023-02-06T02:11:53.088516Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:11:53.088518Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:11:53.755940Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:11:53.755956Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:53.755963Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:53.755988Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:53.755992Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Berlin::0
2023-02-06T02:11:53.755994Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:11:53.755995Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:53.756521Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:11:53.756527Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:53.756531Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:53.756548Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:53.756550Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::London::0
2023-02-06T02:11:53.756552Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:11:53.756554Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:53.756921Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:11:53.756928Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:53.756931Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:53.756950Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:53.756952Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Merge::0
2023-02-06T02:11:53.756953Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:11:53.756955Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:53.757329Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:11:53.757336Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:53.757339Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:53.758368Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:11:53.758390Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:53.784225Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:53.784330Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:53.784334Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:53.784388Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:53.784461Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:53.784466Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Istanbul::0
2023-02-06T02:11:53.784469Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:53.784471Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.168569Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:11:54.168587Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:11:54.168595Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:54.168599Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Berlin::0
2023-02-06T02:11:54.168601Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:54.168603Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.168708Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:11:54.168715Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:11:54.168719Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:54.168721Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::London::0
2023-02-06T02:11:54.168723Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:54.168725Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.168815Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:11:54.168821Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:11:54.168826Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:54.168828Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Merge::0
2023-02-06T02:11:54.168830Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:54.168832Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.168920Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:11:54.168926Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:11:54.169584Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:11:54.169611Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.197982Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:54.198098Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.198103Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:54.198165Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.198240Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:54.198244Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Istanbul::0
2023-02-06T02:11:54.198247Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.198249Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.581316Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:11:54.581339Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:11:54.581345Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.581361Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:54.581366Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Berlin::0
2023-02-06T02:11:54.581368Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.581371Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.581537Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:11:54.581545Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:11:54.581549Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.581561Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:54.581564Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::London::0
2023-02-06T02:11:54.581566Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.581569Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.581674Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:11:54.581680Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:11:54.581684Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.581693Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:54.581695Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Merge::0
2023-02-06T02:11:54.581696Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.581699Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.581792Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:11:54.581797Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:11:54.581800Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.582530Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:11:54.582557Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.606983Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:54.607084Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.607087Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:54.607139Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.607210Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:54.607214Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Istanbul::0
2023-02-06T02:11:54.607217Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.607219Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.970993Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:11:54.971013Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:11:54.971017Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.971031Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:54.971034Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Berlin::0
2023-02-06T02:11:54.971036Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.971038Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.971165Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:11:54.971172Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:11:54.971176Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.971187Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:54.971189Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::London::0
2023-02-06T02:11:54.971192Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.971195Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.971308Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:11:54.971315Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:11:54.971319Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.971329Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:54.971331Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Merge::0
2023-02-06T02:11:54.971333Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.971335Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:54.971430Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:11:54.971440Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:11:54.971443Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:11:54.972047Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:11:54.972070Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:54.995704Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:54.995806Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.995809Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:54.995861Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:54.995933Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:54.995935Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Istanbul::0
2023-02-06T02:11:54.995939Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:54.995941Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:55.358506Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:11:55.358527Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:11:55.358536Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:55.358540Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Berlin::0
2023-02-06T02:11:55.358542Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:55.358544Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:55.358659Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:11:55.358665Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:11:55.358671Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:55.358673Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::London::0
2023-02-06T02:11:55.358676Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:55.358677Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:55.358769Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:11:55.358775Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:11:55.358779Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:55.358781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Merge::0
2023-02-06T02:11:55.358783Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:55.358785Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:55.358876Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:11:55.358882Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:11:55.359802Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:11:55.359832Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.384535Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:55.384639Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:55.384642Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:55.384698Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:55.384771Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:55.384775Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Istanbul::0
2023-02-06T02:11:55.384778Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.384780Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:11:55.995905Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:11:55.995920Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:55.995925Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:55.995951Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:55.995955Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Berlin::0
2023-02-06T02:11:55.995957Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.995959Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:55.996486Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:11:55.996493Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:55.996496Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:55.996514Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:55.996516Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::London::0
2023-02-06T02:11:55.996518Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.996520Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:55.996897Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:11:55.996904Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:55.996907Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:55.996924Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:55.996926Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Merge::0
2023-02-06T02:11:55.996928Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.996930Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:55.997353Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:11:55.997360Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:55.997363Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:55.998240Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:11:55.998260Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.022382Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:56.022490Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:56.022495Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:56.022549Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:56.022622Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:56.022625Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Istanbul::0
2023-02-06T02:11:56.022630Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.022632Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:11:56.649196Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:11:56.649212Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:56.649217Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:56.649242Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:56.649245Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Berlin::0
2023-02-06T02:11:56.649247Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.649249Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:56.649781Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:11:56.649788Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:56.649791Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:56.649809Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:56.649811Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::London::0
2023-02-06T02:11:56.649813Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.649816Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:56.650192Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:11:56.650199Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:56.650202Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:56.650220Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:56.650222Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Merge::0
2023-02-06T02:11:56.650224Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.650226Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:56.650596Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:11:56.650602Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:56.650605Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:56.651535Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:11:56.651559Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:56.675722Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:56.675821Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:56.675825Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:56.675876Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:56.675946Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:56.675950Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Istanbul::0
2023-02-06T02:11:56.675953Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:56.675955Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:11:57.310251Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:11:57.310265Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.310270Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.310300Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:57.310304Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Berlin::0
2023-02-06T02:11:57.310308Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:57.310311Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:57.310860Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:11:57.310867Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.310870Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.310889Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:57.310891Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::London::0
2023-02-06T02:11:57.310893Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:57.310895Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:57.311261Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:11:57.311268Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.311271Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.311290Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:57.311293Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Merge::0
2023-02-06T02:11:57.311295Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:57.311297Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:57.311662Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:11:57.311669Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.311673Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.312660Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:11:57.312685Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:11:57.337528Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:57.337630Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:57.337634Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:57.337685Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:57.337756Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:57.337759Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Istanbul::0
2023-02-06T02:11:57.337762Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:11:57.337764Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:11:57.953116Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:11:57.953130Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.953135Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.953162Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:57.953165Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Berlin::0
2023-02-06T02:11:57.953167Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:11:57.953169Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:11:57.953701Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:11:57.953709Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.953712Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.953730Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:57.953732Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::London::0
2023-02-06T02:11:57.953733Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:11:57.953735Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:11:57.954103Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:11:57.954110Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.954113Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.954130Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:57.954133Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Merge::0
2023-02-06T02:11:57.954135Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:11:57.954137Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:11:57.954511Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:11:57.954517Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:11:57.954520Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:11:57.955377Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:11:57.955399Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:11:57.980831Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:57.980937Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:57.980941Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:57.980994Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:57.981066Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:57.981069Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Istanbul::0
2023-02-06T02:11:57.981073Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:11:57.981075Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.340655Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:11:58.340674Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2509963,
    events_root: None,
}
2023-02-06T02:11:58.340683Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:58.340687Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Berlin::0
2023-02-06T02:11:58.340689Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:11:58.340691Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.340807Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:11:58.340813Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:11:58.340818Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:58.340820Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::London::0
2023-02-06T02:11:58.340822Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:11:58.340823Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.340916Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:11:58.340922Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:11:58.340926Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:58.340928Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Merge::0
2023-02-06T02:11:58.340930Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:11:58.340932Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.341022Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:11:58.341028Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:11:58.341638Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:11:58.341673Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:11:58.366346Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:58.366463Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:58.366466Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:58.366520Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:58.366593Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:58.366596Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Istanbul::0
2023-02-06T02:11:58.366599Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:11:58.366601Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.716448Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:11:58.716467Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8688838,
    events_root: None,
}
2023-02-06T02:11:58.716480Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:58.716483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Berlin::0
2023-02-06T02:11:58.716485Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:11:58.716487Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.716569Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:11:58.716575Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:58.716579Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:58.716581Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::London::0
2023-02-06T02:11:58.716582Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:11:58.716584Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.716652Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:11:58.716657Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:58.716661Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:58.716663Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Merge::0
2023-02-06T02:11:58.716665Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:11:58.716667Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:58.716732Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:11:58.716736Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:58.717501Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:11:58.717528Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:11:58.741538Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:58.741642Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:58.741645Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:58.741696Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:58.741766Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:58.741769Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Istanbul::0
2023-02-06T02:11:58.741773Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:11:58.741775Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.093228Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:11:59.093251Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7674311,
    events_root: None,
}
2023-02-06T02:11:59.093264Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:59.093267Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Berlin::0
2023-02-06T02:11:59.093269Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:11:59.093278Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.093369Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:11:59.093376Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:59.093380Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:59.093382Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::London::0
2023-02-06T02:11:59.093384Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:11:59.093385Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.093452Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:11:59.093457Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:59.093461Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:59.093463Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Merge::0
2023-02-06T02:11:59.093464Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:11:59.093466Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.093549Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:11:59.093555Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:11:59.094391Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:11:59.094413Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:11:59.119547Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:59.119659Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.119662Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:59.119706Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.119708Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:59.119764Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.119766Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-06T02:11:59.119818Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.119820Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-06T02:11:59.119871Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.119942Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:59.119945Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:11:59.119948Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.119950Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.495098Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.495121Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.495134Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:59.495138Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:11:59.495141Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.495143Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.495354Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.495362Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.495370Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:59.495373Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:11:59.495375Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.495394Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.495590Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.495610Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.495625Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:59.495633Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:11:59.495640Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.495647Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.495826Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.495843Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.495858Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:59.495866Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:11:59.495874Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.495881Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.496058Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.496077Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.496093Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:59.496101Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:11:59.496109Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:11:59.496122Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:11:59.496970Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:11:59.496988Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:11:59.498126Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:11:59.498158Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:11:59.525336Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:59.525453Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.525458Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:59.525513Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.525516Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:11:59.525576Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.525652Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:59.525657Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Istanbul::0
2023-02-06T02:11:59.525660Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:11:59.525663Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:11:59.884216Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:11:59.884235Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3615148,
    events_root: None,
}
2023-02-06T02:11:59.884246Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:11:59.884250Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Berlin::0
2023-02-06T02:11:59.884252Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:11:59.884254Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:11:59.884364Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:11:59.884370Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:11:59.884376Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:11:59.884379Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::London::0
2023-02-06T02:11:59.884381Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:11:59.884383Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:11:59.884457Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:11:59.884462Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:11:59.884467Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:11:59.884477Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Merge::0
2023-02-06T02:11:59.884479Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:11:59.884482Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:11:59.884555Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:11:59.884561Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:11:59.885328Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:11:59.885358Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:11:59.909403Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:11:59.909504Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.909507Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:11:59.909558Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:11:59.909628Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:11:59.909631Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Istanbul::0
2023-02-06T02:11:59.909634Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:11:59.909635Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.275406Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:12:00.275425Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:12:00.275435Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:00.275440Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Berlin::0
2023-02-06T02:12:00.275442Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:12:00.275444Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.275565Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:12:00.275572Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:12:00.275578Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:00.275581Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::London::0
2023-02-06T02:12:00.275583Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:12:00.275585Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.275676Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:12:00.275682Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:12:00.275688Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:00.275692Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Merge::0
2023-02-06T02:12:00.275694Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:12:00.275697Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.275788Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:12:00.275794Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:12:00.276409Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:12:00.276432Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:12:00.300527Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:00.300631Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:00.300634Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:00.300688Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:00.300761Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:00.300764Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Istanbul::0
2023-02-06T02:12:00.300768Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:12:00.300771Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.688946Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:12:00.688966Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:12:00.688975Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:00.688980Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Berlin::0
2023-02-06T02:12:00.688981Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:12:00.688983Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.689100Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:12:00.689106Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:12:00.689111Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:00.689114Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::London::0
2023-02-06T02:12:00.689116Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:12:00.689118Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.689203Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:12:00.689208Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:12:00.689212Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:00.689214Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Merge::0
2023-02-06T02:12:00.689216Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:12:00.689218Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:00.689493Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:12:00.689499Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:12:00.690216Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:12:00.690243Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:12:00.715070Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:00.715176Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:00.715179Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:00.715231Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:00.715302Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:00.715305Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Istanbul::0
2023-02-06T02:12:00.715309Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:12:00.715310Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.107233Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:12:01.107256Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:12:01.107267Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:01.107272Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Berlin::0
2023-02-06T02:12:01.107273Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:12:01.107275Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.107391Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:12:01.107397Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:12:01.107404Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:01.107407Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::London::0
2023-02-06T02:12:01.107409Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:12:01.107410Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.107514Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:12:01.107522Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:12:01.107530Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:01.107536Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Merge::0
2023-02-06T02:12:01.107538Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:12:01.107540Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.107648Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:12:01.107654Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:12:01.108573Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:12:01.108603Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:12:01.132717Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:01.132818Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.132821Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:01.132874Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.132946Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:01.132949Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Istanbul::0
2023-02-06T02:12:01.132952Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:12:01.132954Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.484712Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:12:01.484731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746611,
    events_root: None,
}
2023-02-06T02:12:01.484741Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:01.484745Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Berlin::0
2023-02-06T02:12:01.484747Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:12:01.484749Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.484838Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:12:01.484843Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.484847Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:01.484849Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::London::0
2023-02-06T02:12:01.484851Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:12:01.484853Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.484922Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:12:01.484927Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.484931Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:01.484933Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Merge::0
2023-02-06T02:12:01.484935Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:12:01.484937Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.485003Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:12:01.485008Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.485628Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:12:01.485655Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:12:01.510754Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:01.510860Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.510864Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:01.510920Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.511005Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:01.511008Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Istanbul::0
2023-02-06T02:12:01.511012Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:12:01.511014Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.899889Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:12:01.899910Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2743390,
    events_root: None,
}
2023-02-06T02:12:01.899920Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:01.899923Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Berlin::0
2023-02-06T02:12:01.899925Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:12:01.899927Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.900015Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:12:01.900020Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.900024Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:01.900026Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::London::0
2023-02-06T02:12:01.900028Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:12:01.900029Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.900096Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:12:01.900102Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.900106Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:01.900108Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Merge::0
2023-02-06T02:12:01.900110Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:12:01.900111Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:01.900177Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:12:01.900182Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:01.900852Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:12:01.900878Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:01.925281Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:01.925385Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.925389Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:01.925441Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:01.925513Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:01.925516Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Istanbul::0
2023-02-06T02:12:01.925519Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:01.925522Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.293889Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:12:02.293908Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753817,
    events_root: None,
}
2023-02-06T02:12:02.293918Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:02.293921Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Berlin::0
2023-02-06T02:12:02.293923Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:02.293925Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.294010Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:12:02.294017Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.294021Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:02.294024Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::London::0
2023-02-06T02:12:02.294026Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:02.294027Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.294095Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:12:02.294099Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.294104Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:02.294105Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Merge::0
2023-02-06T02:12:02.294107Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:02.294109Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.294190Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:12:02.294196Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.294873Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:12:02.294894Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.320549Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:02.320654Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:02.320658Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:02.320710Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:02.320782Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:02.320785Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Istanbul::0
2023-02-06T02:12:02.320788Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.320790Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.662189Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:12:02.662211Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961071,
    events_root: None,
}
2023-02-06T02:12:02.662220Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:02.662224Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Berlin::0
2023-02-06T02:12:02.662226Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.662228Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.662320Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:12:02.662327Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.662331Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:02.662333Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::London::0
2023-02-06T02:12:02.662335Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.662336Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.662404Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:12:02.662409Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.662413Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:02.662415Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Merge::0
2023-02-06T02:12:02.662417Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.662418Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:02.662484Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:12:02.662489Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:02.663146Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:12:02.663177Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:12:02.687063Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:02.687165Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:02.687169Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:02.687220Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:02.687291Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:02.687294Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Istanbul::0
2023-02-06T02:12:02.687298Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:12:02.687300Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.036719Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:12:03.036737Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-02-06T02:12:03.036747Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:03.036750Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Berlin::0
2023-02-06T02:12:03.036752Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:12:03.036754Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.036858Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:12:03.036864Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.036868Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:03.036870Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::London::0
2023-02-06T02:12:03.036872Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:12:03.036873Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.036954Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:12:03.036961Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.036967Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:03.036970Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Merge::0
2023-02-06T02:12:03.036973Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:12:03.036975Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.037054Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:12:03.037059Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.037732Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:12:03.037753Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:12:03.063703Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:03.063805Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.063809Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:03.063862Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.063935Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:03.063938Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Istanbul::0
2023-02-06T02:12:03.063941Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:12:03.063942Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.435872Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:12:03.435893Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773962,
    events_root: None,
}
2023-02-06T02:12:03.435904Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:03.435908Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Berlin::0
2023-02-06T02:12:03.435909Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:12:03.435911Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.436008Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:12:03.436014Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.436020Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:03.436022Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::London::0
2023-02-06T02:12:03.436024Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:12:03.436026Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.436109Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:12:03.436114Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.436119Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:03.436121Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Merge::0
2023-02-06T02:12:03.436122Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:12:03.436124Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:03.436208Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:12:03.436214Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:03.436993Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:12:03.437020Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.461958Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:03.462057Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.462061Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:03.462113Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.462185Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:03.462188Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Istanbul::0
2023-02-06T02:12:03.462192Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.462194Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:12:03.808950Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:12:03.808970Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000de0b6b3a7640000 },
    gas_used: 4955857,
    events_root: None,
}
2023-02-06T02:12:03.808987Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:03.808992Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Berlin::0
2023-02-06T02:12:03.808996Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.808999Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:12:03.809103Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:12:03.809110Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:12:03.809117Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:03.809119Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::London::0
2023-02-06T02:12:03.809122Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.809124Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:12:03.809214Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:12:03.809221Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:12:03.809226Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:03.809229Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Merge::0
2023-02-06T02:12:03.809231Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.809234Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:12:03.809331Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:12:03.809338Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:12:03.810361Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:12:03.810393Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:12:03.836971Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:03.837102Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.837111Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:03.837171Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:03.837252Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:03.837261Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Istanbul::0
2023-02-06T02:12:03.837299Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:12:03.837308Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:04.194320Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:12:04.194341Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2339024,
    events_root: None,
}
2023-02-06T02:12:04.194352Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:04.194355Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Berlin::0
2023-02-06T02:12:04.194357Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:12:04.194359Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:04.194465Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:12:04.194471Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:04.194476Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:04.194480Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::London::0
2023-02-06T02:12:04.194482Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:12:04.194484Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:04.194553Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:12:04.194558Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:04.194562Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:04.194564Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Merge::0
2023-02-06T02:12:04.194566Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:12:04.194567Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:12:04.194635Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:12:04.194639Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:12:04.195418Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:12:04.195441Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:12:04.221596Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:12:04.221699Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:04.221702Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:12:04.221756Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:12:04.221829Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:12:04.221832Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Istanbul::0
2023-02-06T02:12:04.221835Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:12:04.221837Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-06T02:12:04.885011Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:12:04.885043Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:12:04.885057Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:12:04.885114Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:12:04.885126Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Berlin::0
2023-02-06T02:12:04.885133Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:12:04.885140Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:12:04.885955Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:12:04.885974Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:12:04.885985Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:12:04.886026Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:12:04.886035Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::London::0
2023-02-06T02:12:04.886042Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:12:04.886049Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:12:04.886619Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:12:04.886636Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:12:04.886652Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:12:04.886687Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:12:04.886695Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Merge::0
2023-02-06T02:12:04.886701Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:12:04.886708Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:12:04.887246Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:12:04.887254Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 6000000,
    events_root: None,
}
2023-02-06T02:12:04.887258Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 1,
                    method: 3,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 10,
                    method: 2,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 7,
                    },
                    message: "out of gas",
                },
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:12:04.889124Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:12:04.889724Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 67 Files in Time:26.912554945s
=== Start ===
=== OK Status ===
Count :: 47
{
    "CallRecursiveBomb2.json::CallRecursiveBomb2": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorNotMuchMemory1.json::CallToNameRegistratorNotMuchMemory1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "CallToNameRegistratorZeorSizeMemExpansion.json::CallToNameRegistratorZeorSizeMemExpansion": [
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
    "ABAcalls2.json::ABAcalls2": [
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
    "return1.json::return1": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "return2.json::return2": [
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
    "suicideAddress.json::suicideAddress": [
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
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
    ],
    "ABAcallsSuicide0.json::ABAcallsSuicide0": [
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
    "suicideNotExistingAccount.json::suicideNotExistingAccount": [
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
    "suicideSendEtherToMe.json::suicideSendEtherToMe": [
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
    "CallRecursiveBombLog.json::CallRecursiveBombLog": [
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
    "CallToNameRegistratorOutOfGas.json::CallToNameRegistratorOutOfGas": [
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
    "CallToNameRegistrator0.json::CallToNameRegistrator0": [
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
    "CallToNameRegistratorNotMuchMemory0.json::CallToNameRegistratorNotMuchMemory0": [
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
    "PostToReturn1.json::PostToReturn1": [
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
    "createNameRegistratorOOG_MemExpansionOOV.json::createNameRegistratorOOG_MemExpansionOOV": [
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
    "suicideSendEtherPostDeath.json::suicideSendEtherPostDeath": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "ABAcalls3.json::ABAcalls3": [
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
    "doubleSelfdestructTest.json::doubleSelfdestructTest": [
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
    "Call10.json::Call10": [
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
    "CallToNameRegistratorAddressTooBigLeft.json::CallToNameRegistratorAddressTooBigLeft": [
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
    "CalltoReturn2.json::CalltoReturn2": [
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
    "return0.json::return0": [
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
    "suicideCallerAddresTooBigLeft.json::suicideCallerAddresTooBigLeft": [
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
    "balanceInputAddressTooBig.json::balanceInputAddressTooBig": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
Count :: 22
{
    "callcodeToNameRegistrator0.json::callcodeToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "callcodeToNameRegistratorZeroMemExpanion.json::callcodeToNameRegistratorZeroMemExpanion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "testRandomTest.json::testRandomTest": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorZeroMemExpansion.json::createNameRegistratorZeroMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorOutOfMemoryBonds1.json::createNameRegistratorOutOfMemoryBonds1": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "callcodeToNameRegistratorAddresTooBigRight.json::callcodeToNameRegistratorAddresTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "createNameRegistratorZeroMem.json::createNameRegistratorZeroMem": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorZeorSizeMemExpansion.json::CallToNameRegistratorZeorSizeMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
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
    "createNameRegistratorZeroMem2.json::createNameRegistratorZeroMem2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "CallRecursiveBomb3.json::CallRecursiveBomb3": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorTooMuchMemory0.json::CallToNameRegistratorTooMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorTooMuchMemory1.json::CallToNameRegistratorTooMuchMemory1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistratorAddresTooBigLeft.json::callcodeToNameRegistratorAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "callcodeToReturn1.json::callcodeToReturn1": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallToReturn1ForDynamicJump0.json::CallToReturn1ForDynamicJump0": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
    "createNameRegistrator.json::createNameRegistrator": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorOutOfMemoryBonds0.json::createNameRegistratorOutOfMemoryBonds0": [
        "Istanbul | 0 | ExitCode { value: 38 }",
        "Berlin | 0 | ExitCode { value: 38 }",
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "createWithInvalidOpcode.json::createWithInvalidOpcode": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToReturn1ForDynamicJump1.json::CallToReturn1ForDynamicJump1": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
}
=== SKIP Status ===
None
=== End ===
```
