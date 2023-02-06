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

* Following use-cases are failed, when executed with test vector `transaction.gasLimit` x 10.

- Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| | CallRecursiveBomb0_OOG_atMaxCallDepth |
| | createNameRegistratorOutOfMemoryBonds0 |
| | CallToNameRegistratorMemOOGAndInsufficientBalance |
| | createNameRegistratorOutOfMemoryBonds1 |


- Hit with `EVM_CONTRACT_BAD_JUMPDEST`, ExitCode::39

| Test ID | Use-Case |
| --- | --- |
| | CallToReturn1ForDynamicJump0 |
| | CallToReturn1ForDynamicJump1 |
| |  |
| | |


- Hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION`, ExitCode::35

| Test ID | Use-Case |
| --- | --- |
| | callcodeToReturn1 |
| | callcodeToNameRegistratorAddresTooBigRight |
| | callcodeToNameRegistratorAddresTooBigLeft |
| | callcodeTo0 |
| | callcodeToNameRegistrator0 |


- Hit with error `SYS_OUT_OF_GAS`, (ExitCode::7)

| Test ID | Use-Case |
| | callcodeToNameRegistratorZeroMemExpanion |
| | createNameRegistrator |
| | createNameRegistratorZeroMem2 |
| | CallToNameRegistratorZeorSizeMemExpansion |
| | createWithInvalidOpcode |
| | CallRecursiveBomb3 |
| | CallToNameRegistratorTooMuchMemory1 |
| | CallToNameRegistratorTooMuchMemory0 |
| | CallToNameRegistratorAddressTooBigRight |
| | createNameRegistratorZeroMem |
| | createNameRegistratorZeroMemExpansion |
| | testRandomTest |

> Execution Trace

```
2023-02-06T02:00:54.780969Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stSystemOperationsTest", Total Files :: 67
2023-02-06T02:00:54.781208Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:00:54.809879Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:54.810010Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:54.810013Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:54.810067Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:54.810069Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:54.810127Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:54.810198Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:54.810201Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Istanbul::0
2023-02-06T02:00:54.810204Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:00:54.810206Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.165489Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:00:55.165512Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:00:55.165524Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:55.165529Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Berlin::0
2023-02-06T02:00:55.165531Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:00:55.165533Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.165656Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:00:55.165665Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:00:55.165672Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:55.165675Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::London::0
2023-02-06T02:00:55.165678Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:00:55.165680Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.165797Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:00:55.165803Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:00:55.165810Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:55.165814Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Merge::0
2023-02-06T02:00:55.165817Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T02:00:55.165819Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.165953Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T02:00:55.165960Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-02-06T02:00:55.167474Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T02:00:55.167510Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:00:55.193245Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:55.193360Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.193365Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:55.193420Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.193423Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:55.193482Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.193555Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:55.193558Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Istanbul::0
2023-02-06T02:00:55.193563Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:00:55.193565Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.566047Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:00:55.566067Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 604101208,
    events_root: None,
}
2023-02-06T02:00:55.567353Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:55.567358Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Berlin::0
2023-02-06T02:00:55.567360Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:00:55.567362Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.597881Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:00:55.597916Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 483609872,
    events_root: None,
}
2023-02-06T02:00:55.598845Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:55.598849Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::London::0
2023-02-06T02:00:55.598851Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:00:55.598853Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.630787Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:00:55.630833Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 483609872,
    events_root: None,
}
2023-02-06T02:00:55.631844Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:55.631851Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Merge::0
2023-02-06T02:00:55.631853Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T02:00:55.631855Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:55.663606Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T02:00:55.663649Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 483609872,
    events_root: None,
}
2023-02-06T02:00:55.669742Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T02:00:55.669781Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:00:55.695246Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:55.695355Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.695359Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:55.695411Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.695413Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:55.695471Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:55.695544Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:55.695547Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Istanbul::0
2023-02-06T02:00:55.695550Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:00:55.695552Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.084285Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:00:56.084304Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 846779742,
    events_root: None,
}
2023-02-06T02:00:56.085571Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:56.085576Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Berlin::0
2023-02-06T02:00:56.085578Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:00:56.085580Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.121712Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:00:56.121731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 846882915,
    events_root: None,
}
2023-02-06T02:00:56.123021Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:56.123025Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::London::0
2023-02-06T02:00:56.123028Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:00:56.123029Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.159611Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:00:56.159629Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 845451310,
    events_root: None,
}
2023-02-06T02:00:56.161153Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:56.161159Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Merge::0
2023-02-06T02:00:56.161161Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T02:00:56.161163Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.197555Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T02:00:56.197573Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 845451310,
    events_root: None,
}
2023-02-06T02:00:56.203454Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T02:00:56.203487Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:00:56.228298Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:56.228400Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.228404Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:56.228455Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.228457Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:56.228514Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.228586Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:56.228589Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Istanbul::0
2023-02-06T02:00:56.228592Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:00:56.228595Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.582276Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:00:56.582297Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 99400936,
    events_root: None,
}
2023-02-06T02:00:56.582418Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:56.582422Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Berlin::0
2023-02-06T02:00:56.582424Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:00:56.582426Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.586725Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:00:56.586741Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 99410522,
    events_root: None,
}
2023-02-06T02:00:56.586870Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:56.586874Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::London::0
2023-02-06T02:00:56.586876Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:00:56.586878Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.591013Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:00:56.591021Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 99410522,
    events_root: None,
}
2023-02-06T02:00:56.591143Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:56.591147Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Merge::0
2023-02-06T02:00:56.591149Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T02:00:56.591150Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.595133Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T02:00:56.595142Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 99410522,
    events_root: None,
}
2023-02-06T02:00:56.597377Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T02:00:56.597403Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:00:56.623175Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:56.623278Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.623281Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:56.623335Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.623337Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:56.623393Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.623465Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:56.623468Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Istanbul::0
2023-02-06T02:00:56.623471Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:00:56.623473Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.969966Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:00:56.969985Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631129,
    events_root: None,
}
2023-02-06T02:00:56.969996Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:56.969999Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Berlin::0
2023-02-06T02:00:56.970002Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:00:56.970004Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.970091Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:00:56.970098Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:00:56.970102Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:56.970104Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::London::0
2023-02-06T02:00:56.970106Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:00:56.970107Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.970177Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:00:56.970182Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:00:56.970187Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:56.970189Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Merge::0
2023-02-06T02:00:56.970191Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T02:00:56.970193Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:56.970261Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T02:00:56.970266Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:00:56.971053Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T02:00:56.971077Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:00:56.995772Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:56.995876Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.995879Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:56.995932Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.995935Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:56.995993Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:56.996065Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:56.996067Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::0
2023-02-06T02:00:56.996070Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:56.996072Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.356987Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357007Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:00:57.357016Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 1
2023-02-06T02:00:57.357019Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::1
2023-02-06T02:00:57.357021Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357023Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357168Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357175Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:00:57.357180Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:57.357183Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::0
2023-02-06T02:00:57.357184Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357186Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357310Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357317Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:00:57.357322Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 1
2023-02-06T02:00:57.357324Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::1
2023-02-06T02:00:57.357326Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357328Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357444Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357449Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:00:57.357455Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:57.357457Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::0
2023-02-06T02:00:57.357459Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357461Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357574Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357581Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:00:57.357586Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 1
2023-02-06T02:00:57.357589Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::1
2023-02-06T02:00:57.357591Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357592Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357707Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357713Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:00:57.357718Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:57.357721Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::0
2023-02-06T02:00:57.357722Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357724Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357838Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357844Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T02:00:57.357849Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 1
2023-02-06T02:00:57.357851Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::1
2023-02-06T02:00:57.357853Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T02:00:57.357855Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T02:00:57.357982Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T02:00:57.357989Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T02:00:57.358674Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T02:00:57.358696Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:00:57.383119Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:57.383228Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.383231Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:57.383280Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.383282Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:57.383335Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.383408Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:57.383411Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Istanbul::0
2023-02-06T02:00:57.383414Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:00:57.383415Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:57.737001Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:00:57.737018Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25719303,
    events_root: None,
}
2023-02-06T02:00:57.737055Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:57.737058Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Berlin::0
2023-02-06T02:00:57.737060Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:00:57.737062Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:57.738426Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:00:57.738434Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:00:57.738466Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:57.738468Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::London::0
2023-02-06T02:00:57.738470Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:00:57.738472Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:57.739788Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:00:57.739795Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:00:57.739828Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:57.739830Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Merge::0
2023-02-06T02:00:57.739832Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T02:00:57.739834Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:57.741114Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T02:00:57.741121Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T02:00:57.742389Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T02:00:57.742420Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:00:57.767828Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:57.767930Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.767934Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:57.767985Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.767988Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:57.768046Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:57.768118Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:57.768121Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Istanbul::0
2023-02-06T02:00:57.768124Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:00:57.768126Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.124975Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:00:58.124994Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:00:58.125107Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:58.125110Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Berlin::0
2023-02-06T02:00:58.125112Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:00:58.125114Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.128980Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:00:58.128988Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:00:58.129103Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:58.129107Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::London::0
2023-02-06T02:00:58.129109Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:00:58.129112Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.132909Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:00:58.132916Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:00:58.133033Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:58.133035Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Merge::0
2023-02-06T02:00:58.133037Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T02:00:58.133039Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.136831Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T02:00:58.136840Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:00:58.139460Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T02:00:58.139487Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.164426Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:58.164527Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:58.164530Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:58.164581Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:58.164650Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:58.164653Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Istanbul::0
2023-02-06T02:00:58.164656Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.164658Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.590756Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:00:58.590777Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1905881209,
    events_root: None,
}
2023-02-06T02:00:58.593957Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:58.593973Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Berlin::0
2023-02-06T02:00:58.593977Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.593980Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.685103Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:00:58.685124Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2184795588,
    events_root: None,
}
2023-02-06T02:00:58.687662Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:58.687672Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::London::0
2023-02-06T02:00:58.687675Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.687678Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.689070Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:00:58.689079Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2293561,
    events_root: None,
}
2023-02-06T02:00:58.689084Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:00:58.689097Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:58.689100Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Merge::0
2023-02-06T02:00:58.689102Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.689104Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:58.689240Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T02:00:58.689246Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2293561,
    events_root: None,
}
2023-02-06T02:00:58.689250Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:00:58.696383Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T02:00:58.696425Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:00:58.721052Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:58.721208Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:58.721222Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:58.721304Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:58.721410Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:58.721423Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Istanbul::0
2023-02-06T02:00:58.721432Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:00:58.721439Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.079732Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:00:59.079751Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 192697180,
    events_root: None,
}
2023-02-06T02:00:59.079986Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:59.079990Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Berlin::0
2023-02-06T02:00:59.079992Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:00:59.079994Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.087689Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:00:59.087708Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 205589295,
    events_root: None,
}
2023-02-06T02:00:59.087930Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:59.087934Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::London::0
2023-02-06T02:00:59.087936Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:00:59.087938Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.095733Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:00:59.095744Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 192699015,
    events_root: None,
}
2023-02-06T02:00:59.095987Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:59.095991Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Merge::0
2023-02-06T02:00:59.095993Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T02:00:59.095995Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.103489Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T02:00:59.103502Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 205589295,
    events_root: None,
}
2023-02-06T02:00:59.105756Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T02:00:59.105811Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:00:59.132295Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:59.132422Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.132427Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:59.132501Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.132612Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:59.132617Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Istanbul::0
2023-02-06T02:00:59.132621Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:00:59.132624Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.481926Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:00:59.481946Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 192697173,
    events_root: None,
}
2023-02-06T02:00:59.482178Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:59.482183Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Berlin::0
2023-02-06T02:00:59.482185Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:00:59.482187Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.489620Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:00:59.489637Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 205589285,
    events_root: None,
}
2023-02-06T02:00:59.489853Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:59.489860Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::London::0
2023-02-06T02:00:59.489863Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:00:59.489865Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.497349Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:00:59.497361Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 192699006,
    events_root: None,
}
2023-02-06T02:00:59.497587Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:59.497591Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Merge::0
2023-02-06T02:00:59.497593Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T02:00:59.497595Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.505117Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T02:00:59.505135Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 205589285,
    events_root: None,
}
2023-02-06T02:00:59.506911Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T02:00:59.506938Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:00:59.530141Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:59.530251Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.530255Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:59.530310Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.530384Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:59.530388Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Istanbul::0
2023-02-06T02:00:59.530392Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:00:59.530395Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.920464Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:00:59.920482Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T02:00:59.920488Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:00:59.920527Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:00:59.920531Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Berlin::0
2023-02-06T02:00:59.920534Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:00:59.920537Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.920955Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:00:59.920963Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T02:00:59.920967Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:00:59.920997Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:00:59.921000Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::London::0
2023-02-06T02:00:59.921003Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:00:59.921005Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.921453Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:00:59.921460Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T02:00:59.921464Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:00:59.921495Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:00:59.921498Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Merge::0
2023-02-06T02:00:59.921501Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T02:00:59.921503Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:00:59.921900Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T02:00:59.921907Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T02:00:59.921911Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T02:00:59.922626Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T02:00:59.922654Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:00:59.948239Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:00:59.948343Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.948346Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:00:59.948398Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.948400Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:00:59.948455Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:00:59.948527Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:00:59.948529Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Istanbul::0
2023-02-06T02:00:59.948533Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:00:59.948535Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.306157Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:01:00.306175Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.306294Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:00.306298Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Berlin::0
2023-02-06T02:01:00.306300Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:01:00.306302Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.311075Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:01:00.311088Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.311217Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:00.311220Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::London::0
2023-02-06T02:01:00.311223Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:01:00.311225Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.316843Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:01:00.316862Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.317011Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:00.317016Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Merge::0
2023-02-06T02:01:00.317017Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T02:01:00.317019Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.321612Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T02:01:00.321622Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.323422Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T02:01:00.323450Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:01:00.349398Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:00.349509Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.349513Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:00.349568Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.349570Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:00.349627Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.349699Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:00.349702Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Istanbul::0
2023-02-06T02:01:00.349706Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:01:00.349708Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.696084Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:01:00.696103Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.696231Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:00.696235Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Berlin::0
2023-02-06T02:01:00.696238Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:01:00.696240Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.700534Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:01:00.700541Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.700664Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:00.700667Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::London::0
2023-02-06T02:01:00.700669Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:01:00.700671Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.704835Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:01:00.704843Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.704969Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:00.704971Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Merge::0
2023-02-06T02:01:00.704973Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T02:01:00.704975Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:00.709116Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T02:01:00.709123Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T02:01:00.710511Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T02:01:00.710539Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:01:00.734791Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:00.734914Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.734919Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:00.734978Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.734980Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:00.735036Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:00.735112Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:00.735116Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Istanbul::0
2023-02-06T02:01:00.735119Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:01:00.735121Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.106594Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:01:01.106615Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:01:01.106625Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:01.106628Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Berlin::0
2023-02-06T02:01:01.106630Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:01:01.106632Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.106757Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:01:01.106764Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:01:01.106770Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:01.106772Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::London::0
2023-02-06T02:01:01.106774Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:01:01.106776Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.106888Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:01:01.106894Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:01:01.106899Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:01.106901Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Merge::0
2023-02-06T02:01:01.106903Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T02:01:01.106905Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.107016Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T02:01:01.107022Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-02-06T02:01:01.107747Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T02:01:01.107786Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.132230Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:01.132332Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.132336Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:01.132387Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.132390Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:01.132447Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.132518Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:01.132521Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Istanbul::0
2023-02-06T02:01:01.132525Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.132527Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.490139Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:01:01.490161Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:01:01.490172Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:01.490175Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Berlin::0
2023-02-06T02:01:01.490177Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.490179Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.490301Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:01:01.490307Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:01:01.490313Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:01.490316Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::London::0
2023-02-06T02:01:01.490318Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.490320Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.490453Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:01:01.490459Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:01:01.490464Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:01.490466Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Merge::0
2023-02-06T02:01:01.490469Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.490471Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.490579Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T02:01:01.490586Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-02-06T02:01:01.491227Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T02:01:01.491252Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.515767Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:01.515867Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.515871Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:01.515921Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.515923Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:01.515980Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.516052Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:01.516055Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Istanbul::0
2023-02-06T02:01:01.516058Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.516060Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.909041Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:01:01.909060Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:01.909066Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:01.909079Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:01.909082Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Berlin::0
2023-02-06T02:01:01.909084Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.909087Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.909255Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:01:01.909262Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:01.909265Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:01.909283Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:01.909285Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::London::0
2023-02-06T02:01:01.909287Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.909290Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.909426Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:01:01.909432Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:01.909435Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:01.909443Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:01.909445Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Merge::0
2023-02-06T02:01:01.909447Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.909449Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:01.909580Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T02:01:01.909586Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:01.909589Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:01.910318Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T02:01:01.910340Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:01.934749Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:01.934847Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.934851Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:01.934901Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.934903Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:01.934959Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:01.935029Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:01.935032Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Istanbul::0
2023-02-06T02:01:01.935036Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:01.935038Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.310397Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:01:02.310417Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:01:02.310423Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:02.310436Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:02.310440Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Berlin::0
2023-02-06T02:01:02.310442Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:02.310444Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.310577Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:01:02.310584Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:01:02.310587Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:02.310596Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:02.310598Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::London::0
2023-02-06T02:01:02.310600Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:02.310602Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.310691Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:01:02.310697Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:01:02.310701Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:02.310709Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:02.310711Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Merge::0
2023-02-06T02:01:02.310713Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:02.310716Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.310804Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T02:01:02.310810Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-02-06T02:01:02.310813Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:02.311589Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T02:01:02.311616Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.335820Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:02.335927Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.335931Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:02.335983Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.335985Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:02.336043Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.336114Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:02.336117Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Istanbul::0
2023-02-06T02:01:02.336121Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.336123Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.699213Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:01:02.699234Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:01:02.699245Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:02.699249Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Berlin::0
2023-02-06T02:01:02.699252Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.699254Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.699384Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:01:02.699391Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:01:02.699398Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:02.699403Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::London::0
2023-02-06T02:01:02.699406Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.699408Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.699527Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:01:02.699534Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:01:02.699541Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:02.699544Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Merge::0
2023-02-06T02:01:02.699547Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.699550Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:02.699668Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T02:01:02.699674Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-02-06T02:01:02.700273Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T02:01:02.700301Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:02.725081Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:02.725189Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.725193Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:02.725246Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.725249Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:02.725315Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:02.725389Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:02.725393Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Istanbul::0
2023-02-06T02:01:02.725397Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:02.725400Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.060113Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:01:03.060135Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:01:03.060144Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:03.060148Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Berlin::0
2023-02-06T02:01:03.060150Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:03.060152Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.060308Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:01:03.060314Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:01:03.060320Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:03.060323Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::London::0
2023-02-06T02:01:03.060325Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:03.060326Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.060450Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:01:03.060456Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:01:03.060461Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:03.060464Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Merge::0
2023-02-06T02:01:03.060466Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:03.060468Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.060574Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T02:01:03.060581Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-02-06T02:01:03.061159Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T02:01:03.061183Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.085622Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:03.085773Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.085788Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:03.085864Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.085876Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:03.085959Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.086064Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:03.086076Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Istanbul::0
2023-02-06T02:01:03.086085Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.086092Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.481812Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:01:03.481834Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:01:03.481844Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:03.481847Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Berlin::0
2023-02-06T02:01:03.481849Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.481851Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.481976Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:01:03.481982Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:01:03.481988Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:03.481991Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::London::0
2023-02-06T02:01:03.481993Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.481995Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.482115Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:01:03.482121Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:01:03.482127Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:03.482129Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Merge::0
2023-02-06T02:01:03.482131Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.482133Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.482242Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T02:01:03.482248Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-02-06T02:01:03.482866Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T02:01:03.482893Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.506949Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:03.507053Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.507056Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:03.507107Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.507110Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:03.507184Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.507295Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:03.507299Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Istanbul::0
2023-02-06T02:01:03.507304Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.507307Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.847314Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:01:03.847333Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:03.847338Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:03.847351Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:03.847355Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Berlin::0
2023-02-06T02:01:03.847357Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.847359Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.847465Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:01:03.847471Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:03.847474Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:03.847482Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:03.847484Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::London::0
2023-02-06T02:01:03.847486Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.847489Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.847576Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:01:03.847581Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:03.847584Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:03.847592Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:03.847594Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Merge::0
2023-02-06T02:01:03.847596Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.847598Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:03.847683Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T02:01:03.847689Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:03.847692Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:03.848446Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T02:01:03.848486Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:03.873154Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:03.873265Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.873268Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:03.873330Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.873333Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:03.873400Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:03.873475Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:03.873479Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Istanbul::0
2023-02-06T02:01:03.873482Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:03.873484Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.214050Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:01:04.214070Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:04.214075Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.214087Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:04.214091Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Berlin::0
2023-02-06T02:01:04.214093Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:04.214095Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.214195Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:01:04.214201Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:04.214203Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.214212Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:04.214214Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::London::0
2023-02-06T02:01:04.214216Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:04.214218Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.214303Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:01:04.214308Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:04.214311Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.214319Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:04.214321Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Merge::0
2023-02-06T02:01:04.214323Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:04.214325Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.214408Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T02:01:04.214413Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:04.214416Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.215173Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T02:01:04.215194Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.239071Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:04.239170Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.239173Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:04.239223Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.239225Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:04.239279Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.239349Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:04.239352Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Istanbul::0
2023-02-06T02:01:04.239356Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.239358Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.584099Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:01:04.584120Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:01:04.584131Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:04.584134Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Berlin::0
2023-02-06T02:01:04.584136Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.584139Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.584447Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:01:04.584454Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:01:04.584460Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:04.584463Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::London::0
2023-02-06T02:01:04.584465Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.584467Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.584758Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:01:04.584764Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:01:04.584769Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:04.584771Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Merge::0
2023-02-06T02:01:04.584774Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.584777Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.585067Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T02:01:04.585073Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-02-06T02:01:04.585712Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T02:01:04.585734Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.610974Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:04.611080Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.611083Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:04.611136Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.611138Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:04.611196Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.611269Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:04.611273Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:01:04.611276Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.611278Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.965805Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.965825Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:01:04.965836Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:04.965839Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T02:01:04.965841Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.965844Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.965865Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.965868Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:04.965871Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.965881Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:04.965883Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:01:04.965885Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.965887Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.965998Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966006Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:01:04.966011Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:04.966014Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T02:01:04.966016Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.966018Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.966029Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966032Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:04.966035Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.966041Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:04.966043Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:01:04.966045Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.966047Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.966153Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966160Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:01:04.966165Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:04.966167Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T02:01:04.966169Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.966171Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.966181Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966184Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:04.966187Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.966194Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:04.966195Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:01:04.966197Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.966199Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.966304Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966310Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-02-06T02:01:04.966315Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:04.966318Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T02:01:04.966320Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.966322Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:04.966332Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T02:01:04.966335Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:04.966337Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:04.967086Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T02:01:04.967108Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:01:04.991521Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:04.991621Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.991624Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:04.991675Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.991677Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:04.991735Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:04.991805Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:04.991809Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Istanbul::0
2023-02-06T02:01:04.991812Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:01:04.991814Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.347174Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:01:05.347195Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:01:05.347204Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:05.347208Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Berlin::0
2023-02-06T02:01:05.347209Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:01:05.347211Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.347340Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:01:05.347349Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:01:05.347356Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:05.347359Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::London::0
2023-02-06T02:01:05.347362Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:01:05.347364Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.347488Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:01:05.347495Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:01:05.347500Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:05.347502Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Merge::0
2023-02-06T02:01:05.347504Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T02:01:05.347506Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.347616Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T02:01:05.347622Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-02-06T02:01:05.348292Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T02:01:05.348313Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.374119Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:05.374226Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.374230Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:05.374283Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.374285Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:05.374342Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.374417Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:05.374421Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Istanbul::0
2023-02-06T02:01:05.374424Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.374426Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.772278Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:01:05.772304Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:01:05.772314Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:05.772335Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:05.772339Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Berlin::0
2023-02-06T02:01:05.772342Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.772344Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.772477Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:01:05.772484Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:01:05.772487Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:05.772498Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:05.772500Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::London::0
2023-02-06T02:01:05.772502Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.772504Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.772645Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:01:05.772652Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:01:05.772655Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:05.772664Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:05.772666Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Merge::0
2023-02-06T02:01:05.772668Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.772669Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:05.772805Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T02:01:05.772812Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-02-06T02:01:05.772816Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:05.773862Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T02:01:05.773898Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:05.799984Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:05.800087Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.800090Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:05.800142Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.800144Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:05.800202Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:05.800274Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:05.800277Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Istanbul::0
2023-02-06T02:01:05.800281Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:05.800283Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.136349Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:01:06.136370Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:01:06.136375Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:06.136389Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:06.136393Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Berlin::0
2023-02-06T02:01:06.136395Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:06.136398Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.136540Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:01:06.136546Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:01:06.136549Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:06.136559Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:06.136561Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::London::0
2023-02-06T02:01:06.136564Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:06.136566Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.136678Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:01:06.136684Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:01:06.136688Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:06.136697Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:06.136699Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Merge::0
2023-02-06T02:01:06.136701Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:06.136703Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.136812Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T02:01:06.136818Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-02-06T02:01:06.136821Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:06.137458Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T02:01:06.137478Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:01:06.161703Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:06.161808Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.161812Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:06.161864Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.161866Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:06.161924Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.161996Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:06.161999Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Istanbul::0
2023-02-06T02:01:06.162002Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:01:06.162004Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.530193Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:01:06.530212Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:01:06.530222Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:06.530225Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Berlin::0
2023-02-06T02:01:06.530227Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:01:06.530229Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.530373Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:01:06.530380Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:01:06.530386Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:06.530388Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::London::0
2023-02-06T02:01:06.530390Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:01:06.530392Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.530538Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:01:06.530544Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:01:06.530550Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:06.530552Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Merge::0
2023-02-06T02:01:06.530554Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T02:01:06.530556Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:06.530668Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T02:01:06.530673Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-02-06T02:01:06.531266Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T02:01:06.531294Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:01:06.557413Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:06.557517Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.557521Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:06.557574Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.557577Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:06.557634Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:06.557709Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:06.557712Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Istanbul::0
2023-02-06T02:01:06.557716Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:01:06.557719Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:07.010446Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:01:07.010466Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3909237,
    events_root: None,
}
2023-02-06T02:01:07.010480Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:07.010483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Berlin::0
2023-02-06T02:01:07.010485Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:01:07.010487Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T02:01:07.171517Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:01:07.171532Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13534900,
    events_root: None,
}
2023-02-06T02:01:07.171556Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:07.171560Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::London::0
2023-02-06T02:01:07.171562Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:01:07.171564Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T02:01:07.172188Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:01:07.172195Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-02-06T02:01:07.172212Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:07.172215Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Merge::0
2023-02-06T02:01:07.172219Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T02:01:07.172220Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T02:01:07.172792Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T02:01:07.172799Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-02-06T02:01:07.173769Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T02:01:07.173797Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:01:07.197992Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:07.198093Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.198096Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:07.198148Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.198151Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:07.198207Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.198277Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:07.198280Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Istanbul::0
2023-02-06T02:01:07.198284Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:01:07.198286Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:07.554257Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:01:07.554280Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2702051,
    events_root: None,
}
2023-02-06T02:01:07.554294Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:07.554298Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Berlin::0
2023-02-06T02:01:07.554300Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:01:07.554301Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:07.554464Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:01:07.554471Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:01:07.554478Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:07.554481Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::London::0
2023-02-06T02:01:07.554483Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:01:07.554484Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:07.554606Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:01:07.554613Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:01:07.554618Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:07.554620Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Merge::0
2023-02-06T02:01:07.554621Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T02:01:07.554623Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:07.554744Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T02:01:07.554752Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-02-06T02:01:07.555570Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T02:01:07.555592Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:01:07.579973Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:07.580076Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.580080Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:07.580133Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.580205Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:07.580208Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Istanbul::0
2023-02-06T02:01:07.580211Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:01:07.580213Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:01:07.936824Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:01:07.936845Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2563734,
    events_root: None,
}
2023-02-06T02:01:07.936855Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:07.936858Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Berlin::0
2023-02-06T02:01:07.936860Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:01:07.936862Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:01:07.936975Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:01:07.936981Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:01:07.936986Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:07.936988Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::London::0
2023-02-06T02:01:07.936990Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:01:07.936992Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:01:07.937083Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:01:07.937089Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:01:07.937093Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:07.937095Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Merge::0
2023-02-06T02:01:07.937097Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T02:01:07.937099Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T02:01:07.937189Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T02:01:07.937195Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-02-06T02:01:07.937831Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T02:01:07.937859Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:01:07.961763Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:07.961869Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.961872Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:07.961925Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:07.961998Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:07.962001Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Istanbul::0
2023-02-06T02:01:07.962004Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:01:07.962006Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.321011Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:01:08.321032Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:01:08.321040Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:08.321045Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Berlin::0
2023-02-06T02:01:08.321047Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:01:08.321049Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.321186Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:01:08.321193Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:01:08.321198Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:08.321200Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::London::0
2023-02-06T02:01:08.321201Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:01:08.321203Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.321311Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:01:08.321317Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:01:08.321322Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:08.321324Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Merge::0
2023-02-06T02:01:08.321326Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T02:01:08.321328Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.321428Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T02:01:08.321434Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-02-06T02:01:08.322083Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T02:01:08.322109Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:01:08.346480Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:08.346586Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:08.346589Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:08.346642Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:08.346714Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:08.346718Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Istanbul::0
2023-02-06T02:01:08.346720Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:01:08.346723Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.720468Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:01:08.720489Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:01:08.720498Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:08.720502Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Berlin::0
2023-02-06T02:01:08.720503Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:01:08.720505Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.720613Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:01:08.720619Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:01:08.720623Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:08.720625Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::London::0
2023-02-06T02:01:08.720627Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:01:08.720629Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.720718Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:01:08.720723Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:01:08.720728Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:08.720730Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Merge::0
2023-02-06T02:01:08.720731Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T02:01:08.720733Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:08.720824Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T02:01:08.720829Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T02:01:08.721445Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T02:01:08.721476Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:01:08.745725Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:08.745832Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:08.745836Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:08.745893Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:08.745965Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:08.745968Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Istanbul::0
2023-02-06T02:01:08.745971Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:01:08.745974Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.083181Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:01:09.083201Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:01:09.083207Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.083221Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:09.083225Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Berlin::0
2023-02-06T02:01:09.083227Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:01:09.083229Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.083349Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:01:09.083356Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:01:09.083359Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.083367Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:09.083370Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::London::0
2023-02-06T02:01:09.083372Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:01:09.083373Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.083463Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:01:09.083468Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:01:09.083472Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.083482Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:09.083484Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Merge::0
2023-02-06T02:01:09.083486Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T02:01:09.083487Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.083571Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T02:01:09.083576Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T02:01:09.083579Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.084370Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T02:01:09.084405Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.108322Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:09.108428Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.108431Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:09.108485Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.108487Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:09.108542Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.108613Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:09.108616Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Istanbul::0
2023-02-06T02:01:09.108619Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.108621Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.457628Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:01:09.457650Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:09.457655Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.457668Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:09.457671Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Berlin::0
2023-02-06T02:01:09.457673Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.457675Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.457785Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:01:09.457791Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:09.457794Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.457804Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:09.457806Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::London::0
2023-02-06T02:01:09.457808Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.457810Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.457907Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:01:09.457913Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:09.457917Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.457927Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:09.457930Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Merge::0
2023-02-06T02:01:09.457932Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.457935Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.458034Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T02:01:09.458040Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:09.458043Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.458741Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T02:01:09.458762Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.483755Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:09.483856Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.483859Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:09.483912Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.483914Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:09.483972Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.484043Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:09.484047Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Istanbul::0
2023-02-06T02:01:09.484051Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.484053Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.881150Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:01:09.881170Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:09.881176Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.881188Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:09.881192Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Berlin::0
2023-02-06T02:01:09.881194Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.881196Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.881324Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:01:09.881331Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:09.881334Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.881342Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:09.881344Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::London::0
2023-02-06T02:01:09.881346Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.881349Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.881440Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:01:09.881446Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:09.881449Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.881457Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:09.881459Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Merge::0
2023-02-06T02:01:09.881461Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.881463Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:09.881550Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T02:01:09.881555Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:09.881558Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:09.882141Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T02:01:09.882162Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:09.905607Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:09.905705Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.905709Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:09.905759Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.905761Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:09.905816Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:09.905885Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:09.905888Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Istanbul::0
2023-02-06T02:01:09.905891Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:09.905894Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.236262Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:01:10.236283Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:10.236289Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.236302Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:10.236305Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Berlin::0
2023-02-06T02:01:10.236308Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:10.236311Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.236435Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:01:10.236442Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:10.236445Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.236454Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:10.236456Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::London::0
2023-02-06T02:01:10.236458Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:10.236460Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.236549Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:01:10.236555Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:10.236558Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.236566Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:10.236568Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Merge::0
2023-02-06T02:01:10.236570Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:10.236572Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.236668Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T02:01:10.236673Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-02-06T02:01:10.236677Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.237346Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T02:01:10.237368Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.261909Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:10.262017Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.262020Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:10.262072Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.262075Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:10.262131Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.262205Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:10.262209Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:01:10.262212Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.262214Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.593874Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.593895Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:10.593902Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.593913Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:10.593917Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T02:01:10.593919Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.593921Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594099Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594105Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:10.594108Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594117Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:10.594119Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:01:10.594122Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594124Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594134Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594137Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:10.594140Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594145Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:10.594147Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T02:01:10.594149Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594151Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594243Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594249Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:10.594252Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594260Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:10.594262Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:01:10.594264Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594268Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594278Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594281Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:10.594284Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594290Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:10.594291Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T02:01:10.594293Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594295Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594388Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594394Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:10.594397Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594405Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:10.594406Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:01:10.594408Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594411Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594421Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594424Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T02:01:10.594426Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.594432Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:10.594434Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T02:01:10.594435Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.594438Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:10.594522Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T02:01:10.594528Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:10.594531Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:10.595179Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T02:01:10.595200Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:01:10.619330Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:10.619454Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.619459Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:10.619526Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.619530Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:10.619604Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:10.619704Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:10.619709Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Istanbul::0
2023-02-06T02:01:10.619713Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:01:10.619716Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.013938Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:01:11.013962Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:11.013968Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:11.013980Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:11.013983Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Berlin::0
2023-02-06T02:01:11.013985Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:01:11.013987Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.014107Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:01:11.014113Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:11.014116Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:11.014124Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:11.014126Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::London::0
2023-02-06T02:01:11.014128Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:01:11.014130Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.014217Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:01:11.014223Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:11.014226Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:11.014235Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:11.014237Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Merge::0
2023-02-06T02:01:11.014239Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T02:01:11.014240Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.014327Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T02:01:11.014332Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T02:01:11.014335Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:11.015014Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T02:01:11.015045Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:01:11.038783Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:11.038885Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:11.038889Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:11.038943Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:11.039016Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:11.039019Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Istanbul::0
2023-02-06T02:01:11.039022Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:01:11.039024Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.402597Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:01:11.402619Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2479617,
    events_root: None,
}
2023-02-06T02:01:11.402628Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:11.402632Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Berlin::0
2023-02-06T02:01:11.402633Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:01:11.402635Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.402773Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:01:11.402779Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:01:11.402784Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:11.402786Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::London::0
2023-02-06T02:01:11.402788Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:01:11.402790Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.402885Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:01:11.402891Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:01:11.402895Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:11.402897Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Merge::0
2023-02-06T02:01:11.402899Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T02:01:11.402901Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:11.402990Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T02:01:11.402995Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T02:01:11.403775Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T02:01:11.403803Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:01:11.427692Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:11.427790Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:11.427794Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:11.427845Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:11.427923Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:11.427925Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Istanbul::0
2023-02-06T02:01:11.427929Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:01:11.427931Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.035422Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:01:12.035444Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:12.035450Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.035477Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:12.035481Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Berlin::0
2023-02-06T02:01:12.035483Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:01:12.035491Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.035903Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:01:12.035911Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:12.035915Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.035933Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:12.035935Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::London::0
2023-02-06T02:01:12.035937Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:01:12.035938Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.036132Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:01:12.036140Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:12.036143Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.036159Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:12.036161Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Merge::0
2023-02-06T02:01:12.036163Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T02:01:12.036165Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.036353Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T02:01:12.036360Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:12.036365Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.037629Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T02:01:12.037660Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.062116Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:12.062218Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.062221Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:12.062275Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.062347Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:12.062350Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Istanbul::0
2023-02-06T02:01:12.062353Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.062355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.412030Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:01:12.412055Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:01:12.412065Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:12.412070Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Berlin::0
2023-02-06T02:01:12.412073Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.412075Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.412201Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:01:12.412210Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:01:12.412216Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:12.412219Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::London::0
2023-02-06T02:01:12.412221Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.412224Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.412321Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:01:12.412329Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:01:12.412336Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:12.412339Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Merge::0
2023-02-06T02:01:12.412342Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.412346Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.412441Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T02:01:12.412449Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-02-06T02:01:12.413080Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T02:01:12.413109Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.437845Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:12.437955Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.437959Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:12.438016Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.438091Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:12.438095Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Istanbul::0
2023-02-06T02:01:12.438099Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.438102Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.780830Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:01:12.780850Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:01:12.780857Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.780871Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:12.780876Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Berlin::0
2023-02-06T02:01:12.780879Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.780882Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.781016Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:01:12.781023Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:01:12.781027Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.781039Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:12.781042Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::London::0
2023-02-06T02:01:12.781046Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.781049Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.781148Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:01:12.781154Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:01:12.781158Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.781170Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:12.781172Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Merge::0
2023-02-06T02:01:12.781176Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.781179Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:12.781289Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T02:01:12.781297Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-02-06T02:01:12.781300Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:12.782048Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T02:01:12.782073Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:12.806252Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:12.806361Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.806364Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:12.806423Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:12.806497Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:12.806500Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Istanbul::0
2023-02-06T02:01:12.806503Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:12.806506Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.164367Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:01:13.164388Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:01:13.164394Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:13.164407Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:13.164411Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Berlin::0
2023-02-06T02:01:13.164413Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:13.164415Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.164526Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:01:13.164533Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:01:13.164536Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:13.164545Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:13.164547Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::London::0
2023-02-06T02:01:13.164549Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:13.164551Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.164645Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:01:13.164651Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:01:13.164654Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:13.164662Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:13.164664Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Merge::0
2023-02-06T02:01:13.164666Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:13.164668Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.164759Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T02:01:13.164765Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-02-06T02:01:13.164768Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:13.165561Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T02:01:13.165582Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.189616Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:13.189721Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:13.189725Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:13.189788Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:13.189860Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:13.189864Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Istanbul::0
2023-02-06T02:01:13.189867Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.189869Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.535577Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:01:13.535597Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:01:13.535607Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:13.535610Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Berlin::0
2023-02-06T02:01:13.535613Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.535615Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.535724Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:01:13.535731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:01:13.535736Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:13.535738Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::London::0
2023-02-06T02:01:13.535740Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.535742Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.535836Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:01:13.535842Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:01:13.535846Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:13.535848Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Merge::0
2023-02-06T02:01:13.535850Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.535852Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:13.535943Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T02:01:13.535948Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-02-06T02:01:13.536625Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T02:01:13.536650Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:01:13.560761Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:13.560867Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:13.560871Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:13.560924Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:13.560996Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:13.560999Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Istanbul::0
2023-02-06T02:01:13.561002Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:01:13.561004Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.190662Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:01:14.190684Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.190690Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.190714Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:14.190718Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Berlin::0
2023-02-06T02:01:14.190721Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:01:14.190723Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.191144Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:01:14.191152Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.191155Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.191171Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:14.191173Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::London::0
2023-02-06T02:01:14.191175Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:01:14.191177Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.191368Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:01:14.191375Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.191378Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.191393Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:14.191395Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Merge::0
2023-02-06T02:01:14.191397Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T02:01:14.191399Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.191588Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T02:01:14.191594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.191597Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.192682Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T02:01:14.192704Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.216690Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:14.216793Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:14.216797Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:14.216851Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:14.216924Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:14.216927Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Istanbul::0
2023-02-06T02:01:14.216930Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.216932Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.837220Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:01:14.837239Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.837244Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.837281Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:14.837287Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Berlin::0
2023-02-06T02:01:14.837289Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.837292Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.837700Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:01:14.837708Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.837712Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.837730Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:14.837732Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::London::0
2023-02-06T02:01:14.837734Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.837736Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.837926Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:01:14.837932Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.837936Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.837952Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:14.837954Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Merge::0
2023-02-06T02:01:14.837956Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.837959Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:14.838145Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T02:01:14.838153Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:14.838157Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:14.839242Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T02:01:14.839269Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:14.863969Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:14.864069Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:14.864073Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:14.864127Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:14.864200Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:14.864204Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Istanbul::0
2023-02-06T02:01:14.864207Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:14.864210Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.480896Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:01:15.480913Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.480919Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:15.480943Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:15.480947Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Berlin::0
2023-02-06T02:01:15.480949Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:15.480951Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.481335Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:01:15.481342Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.481346Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:15.481362Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:15.481365Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::London::0
2023-02-06T02:01:15.481368Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:15.481370Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.481587Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:01:15.481595Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.481598Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:15.481615Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:15.481617Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Merge::0
2023-02-06T02:01:15.481619Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:15.481622Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.481807Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T02:01:15.481813Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.481817Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:15.482671Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T02:01:15.482697Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:01:15.506713Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:15.506815Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:15.506819Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:15.506873Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:15.506960Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:15.506964Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Istanbul::0
2023-02-06T02:01:15.506968Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:01:15.506970Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.956789Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:01:15.956809Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.956814Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
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
2023-02-06T02:01:15.956833Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:15.956837Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Berlin::0
2023-02-06T02:01:15.956839Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:01:15.956841Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.957124Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:01:15.957131Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.957135Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
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
2023-02-06T02:01:15.957148Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:15.957150Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::London::0
2023-02-06T02:01:15.957152Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:01:15.957153Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.957343Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:01:15.957349Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.957352Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
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
2023-02-06T02:01:15.957366Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:15.957368Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Merge::0
2023-02-06T02:01:15.957370Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T02:01:15.957372Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:15.957551Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T02:01:15.957557Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:15.957560Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
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
2023-02-06T02:01:15.958337Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T02:01:15.958369Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:01:15.981916Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:15.982017Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:15.982020Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:15.982072Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:15.982144Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:15.982147Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Istanbul::0
2023-02-06T02:01:15.982149Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:01:15.982152Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.334461Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:01:16.334483Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2509963,
    events_root: None,
}
2023-02-06T02:01:16.334493Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:16.334496Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Berlin::0
2023-02-06T02:01:16.334498Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:01:16.334500Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.334614Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:01:16.334621Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:01:16.334626Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:16.334628Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::London::0
2023-02-06T02:01:16.334630Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:01:16.334631Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.334725Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:01:16.334731Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:01:16.334736Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:16.334738Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Merge::0
2023-02-06T02:01:16.334740Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T02:01:16.334741Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.334833Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T02:01:16.334839Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T02:01:16.335514Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T02:01:16.335538Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:01:16.359566Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:16.359672Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:16.359675Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:16.359730Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:16.359802Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:16.359805Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Istanbul::0
2023-02-06T02:01:16.359808Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:01:16.359810Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.712630Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:01:16.712649Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8688838,
    events_root: None,
}
2023-02-06T02:01:16.712661Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:16.712665Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Berlin::0
2023-02-06T02:01:16.712667Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:01:16.712669Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.712757Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:01:16.712763Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:16.712768Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:16.712770Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::London::0
2023-02-06T02:01:16.712773Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:01:16.712775Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.712847Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:01:16.712852Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:16.712856Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:16.712858Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Merge::0
2023-02-06T02:01:16.712860Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T02:01:16.712862Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:16.712928Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T02:01:16.712933Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:16.713695Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T02:01:16.713718Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:01:16.737432Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:16.737531Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:16.737535Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:16.737586Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:16.737657Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:16.737660Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Istanbul::0
2023-02-06T02:01:16.737664Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:01:16.737667Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.071862Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:01:17.071878Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7674311,
    events_root: None,
}
2023-02-06T02:01:17.071891Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:17.071894Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Berlin::0
2023-02-06T02:01:17.071896Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:01:17.071898Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.071979Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:01:17.071984Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:17.071988Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:17.071990Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::London::0
2023-02-06T02:01:17.071992Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:01:17.071994Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.072058Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:01:17.072063Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:17.072067Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:17.072068Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Merge::0
2023-02-06T02:01:17.072071Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T02:01:17.072072Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.072135Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T02:01:17.072140Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:17.072792Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T02:01:17.072821Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:01:17.096574Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:17.096682Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.096686Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:17.096733Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.096736Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:17.096795Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.096798Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-06T02:01:17.096853Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.096856Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-06T02:01:17.096910Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.096983Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:17.096987Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:01:17.096991Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.096995Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474104Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474121Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.474133Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:17.474137Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:01:17.474139Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.474142Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474287Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474294Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.474302Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:17.474305Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T02:01:17.474308Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.474310Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474465Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474472Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.474480Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:17.474483Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:01:17.474486Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.474488Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474619Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474626Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.474633Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:17.474636Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:01:17.474639Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.474642Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474773Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474780Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.474787Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:17.474791Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T02:01:17.474794Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T02:01:17.474796Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:17.474925Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T02:01:17.474932Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T02:01:17.475581Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T02:01:17.475604Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:01:17.499434Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:17.499540Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.499544Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:17.499600Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.499603Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T02:01:17.499662Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.499735Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:17.499739Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Istanbul::0
2023-02-06T02:01:17.499743Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:01:17.499747Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:01:17.841712Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:01:17.841734Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3615148,
    events_root: None,
}
2023-02-06T02:01:17.841746Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:17.841750Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Berlin::0
2023-02-06T02:01:17.841752Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:01:17.841754Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:01:17.841857Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:01:17.841863Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:01:17.841869Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:17.841872Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::London::0
2023-02-06T02:01:17.841875Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:01:17.841877Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:01:17.841950Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:01:17.841956Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:01:17.841961Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:17.841964Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Merge::0
2023-02-06T02:01:17.841966Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T02:01:17.841969Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T02:01:17.842048Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T02:01:17.842054Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T02:01:17.842840Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T02:01:17.842864Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:01:17.866433Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:17.866533Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.866537Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:17.866589Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:17.866660Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:17.866663Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Istanbul::0
2023-02-06T02:01:17.866666Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:01:17.866668Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.205896Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:01:18.205915Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:01:18.205925Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:18.205928Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Berlin::0
2023-02-06T02:01:18.205930Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:01:18.205932Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.206048Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:01:18.206054Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:01:18.206059Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:18.206061Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::London::0
2023-02-06T02:01:18.206063Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:01:18.206064Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.206152Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:01:18.206157Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:01:18.206161Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:18.206163Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Merge::0
2023-02-06T02:01:18.206165Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T02:01:18.206167Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.206250Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T02:01:18.206255Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-02-06T02:01:18.206914Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T02:01:18.206940Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:01:18.230771Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:18.230874Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.230878Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:18.230932Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.231004Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:18.231007Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Istanbul::0
2023-02-06T02:01:18.231010Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:01:18.231012Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.592643Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:01:18.592665Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:01:18.592677Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:18.592682Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Berlin::0
2023-02-06T02:01:18.592684Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:01:18.592686Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.592819Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:01:18.592825Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:01:18.592832Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:18.592835Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::London::0
2023-02-06T02:01:18.592838Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:01:18.592840Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.592930Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:01:18.592936Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:01:18.592942Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:18.592945Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Merge::0
2023-02-06T02:01:18.592948Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T02:01:18.592950Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.593040Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T02:01:18.593046Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-02-06T02:01:18.593718Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T02:01:18.593742Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:01:18.617196Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:18.617311Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.617316Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:18.617371Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.617445Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:18.617449Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Istanbul::0
2023-02-06T02:01:18.617452Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:01:18.617455Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.964047Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:01:18.964066Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:01:18.964077Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:18.964081Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Berlin::0
2023-02-06T02:01:18.964082Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:01:18.964084Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.964183Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:01:18.964189Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:01:18.964195Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:18.964197Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::London::0
2023-02-06T02:01:18.964199Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:01:18.964200Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.964282Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:01:18.964287Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:01:18.964293Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:18.964295Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Merge::0
2023-02-06T02:01:18.964297Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T02:01:18.964298Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:18.964380Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T02:01:18.964385Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-02-06T02:01:18.964974Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T02:01:18.965004Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:01:18.988640Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:18.988736Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.988739Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:18.988789Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:18.988858Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:18.988861Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Istanbul::0
2023-02-06T02:01:18.988865Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:01:18.988867Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.321305Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:01:19.321327Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746611,
    events_root: None,
}
2023-02-06T02:01:19.321339Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:19.321343Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Berlin::0
2023-02-06T02:01:19.321345Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:01:19.321348Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.321440Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:01:19.321446Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.321452Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:19.321455Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::London::0
2023-02-06T02:01:19.321458Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:01:19.321461Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.321537Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:01:19.321543Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.321548Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:19.321551Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Merge::0
2023-02-06T02:01:19.321554Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T02:01:19.321556Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.321626Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T02:01:19.321632Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.322239Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T02:01:19.322266Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:01:19.346507Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:19.346611Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:19.346615Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:19.346669Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:19.346741Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:19.346745Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Istanbul::0
2023-02-06T02:01:19.346749Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:01:19.346752Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.703875Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:01:19.703895Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2743390,
    events_root: None,
}
2023-02-06T02:01:19.703907Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:19.703911Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Berlin::0
2023-02-06T02:01:19.703914Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:01:19.703916Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.704028Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:01:19.704035Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.704040Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:19.704043Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::London::0
2023-02-06T02:01:19.704046Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:01:19.704048Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.704123Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:01:19.704129Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.704134Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:19.704137Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Merge::0
2023-02-06T02:01:19.704140Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T02:01:19.704142Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:19.704223Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T02:01:19.704229Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:19.704983Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T02:01:19.705007Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:19.729045Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:19.729153Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:19.729157Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:19.729213Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:19.729298Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:19.729302Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Istanbul::0
2023-02-06T02:01:19.729307Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:19.729309Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.067945Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:01:20.067970Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753817,
    events_root: None,
}
2023-02-06T02:01:20.067982Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:20.067987Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Berlin::0
2023-02-06T02:01:20.067989Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:20.067992Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.068105Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:01:20.068113Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.068117Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:20.068119Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::London::0
2023-02-06T02:01:20.068122Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:20.068123Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.068196Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:01:20.068201Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.068206Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:20.068208Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Merge::0
2023-02-06T02:01:20.068210Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:20.068212Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.068279Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T02:01:20.068284Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.069019Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T02:01:20.069044Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.093464Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:20.093570Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.093574Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:20.093643Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.093735Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:20.093741Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Istanbul::0
2023-02-06T02:01:20.093745Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.093747Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.430601Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:01:20.430622Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961071,
    events_root: None,
}
2023-02-06T02:01:20.430631Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:20.430635Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Berlin::0
2023-02-06T02:01:20.430637Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.430639Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.430731Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:01:20.430738Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.430742Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:20.430744Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::London::0
2023-02-06T02:01:20.430746Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.430748Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.430818Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:01:20.430823Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.430828Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:20.430829Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Merge::0
2023-02-06T02:01:20.430832Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.430833Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.430902Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T02:01:20.430907Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.431613Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T02:01:20.431639Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:01:20.455774Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:20.455875Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.455880Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:20.455932Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.456005Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:20.456008Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Istanbul::0
2023-02-06T02:01:20.456011Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:01:20.456013Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.817120Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:01:20.817140Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-02-06T02:01:20.817150Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:20.817154Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Berlin::0
2023-02-06T02:01:20.817156Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:01:20.817158Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.817261Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:01:20.817267Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.817282Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:20.817284Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::London::0
2023-02-06T02:01:20.817287Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:01:20.817289Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.817365Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:01:20.817370Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.817375Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:20.817377Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Merge::0
2023-02-06T02:01:20.817380Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T02:01:20.817382Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:20.817455Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T02:01:20.817460Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:20.818046Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T02:01:20.818072Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:01:20.842775Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:20.842880Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.842884Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:20.842938Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:20.843010Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:20.843013Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Istanbul::0
2023-02-06T02:01:20.843016Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:01:20.843018Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:21.195259Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:01:21.195278Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773962,
    events_root: None,
}
2023-02-06T02:01:21.195288Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:21.195292Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Berlin::0
2023-02-06T02:01:21.195294Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:01:21.195296Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:21.195383Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:01:21.195389Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:21.195393Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:21.195395Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::London::0
2023-02-06T02:01:21.195397Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:01:21.195399Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:21.195467Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:01:21.195472Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:21.195476Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:21.195478Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Merge::0
2023-02-06T02:01:21.195480Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T02:01:21.195481Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:21.195548Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T02:01:21.195553Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:21.196247Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T02:01:21.196277Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.222254Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:21.222359Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:21.222362Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:21.222415Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:21.222489Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:21.222492Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Istanbul::0
2023-02-06T02:01:21.222495Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.222497Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:01:21.632389Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:01:21.632409Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000de0b6b3a7640000 },
    gas_used: 4955857,
    events_root: None,
}
2023-02-06T02:01:21.632425Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:21.632429Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Berlin::0
2023-02-06T02:01:21.632431Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.632433Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:01:21.632520Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:01:21.632526Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:01:21.632530Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:21.632532Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::London::0
2023-02-06T02:01:21.632534Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.632536Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:01:21.632605Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:01:21.632611Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:01:21.632615Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:21.632617Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Merge::0
2023-02-06T02:01:21.632619Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.632621Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T02:01:21.632689Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T02:01:21.632693Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-02-06T02:01:21.633355Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T02:01:21.633381Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:01:21.658093Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:21.658197Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:21.658200Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:21.658252Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:21.658324Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:21.658327Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Istanbul::0
2023-02-06T02:01:21.658330Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:01:21.658332Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.007309Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:01:22.007330Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2339024,
    events_root: None,
}
2023-02-06T02:01:22.007340Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:22.007344Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Berlin::0
2023-02-06T02:01:22.007346Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:01:22.007348Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.007441Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:01:22.007447Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:22.007451Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:22.007453Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::London::0
2023-02-06T02:01:22.007455Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:01:22.007457Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.007523Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:01:22.007528Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:22.007533Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:22.007535Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Merge::0
2023-02-06T02:01:22.007537Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T02:01:22.007539Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.007605Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T02:01:22.007610Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T02:01:22.008191Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T02:01:22.008215Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:01:22.032174Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T02:01:22.032274Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:22.032278Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T02:01:22.032330Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T02:01:22.032401Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T02:01:22.032403Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Istanbul::0
2023-02-06T02:01:22.032407Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:01:22.032408Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.701234Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:01:22.701284Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:22.701294Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:22.701348Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T02:01:22.701357Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Berlin::0
2023-02-06T02:01:22.701361Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:01:22.701364Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.702116Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:01:22.702127Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:22.702132Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:22.702154Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T02:01:22.702158Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::London::0
2023-02-06T02:01:22.702160Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:01:22.702162Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.702416Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:01:22.702424Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:22.702428Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:22.702450Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T02:01:22.702453Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Merge::0
2023-02-06T02:01:22.702455Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T02:01:22.702458Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T02:01:22.702699Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T02:01:22.702707Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T02:01:22.702711Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T02:01:22.704522Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T02:01:22.705018Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 67 Files in Time:26.2053429s
=== Start ===
=== OK Status ===
Count :: 46
{
    "CallToNameRegistratorNotMuchMemory1.json::CallToNameRegistratorNotMuchMemory1": [
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
    "CallToNameRegistrator0.json::CallToNameRegistrator0": [
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
    "suicideNotExistingAccount.json::suicideNotExistingAccount": [
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
    "CallToNameRegistratorTooMuchMemory2.json::CallToNameRegistratorTooMuchMemory2": [
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
    "createNameRegistratorValueTooHigh.json::createNameRegistratorValueTooHigh": [
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
    "doubleSelfdestructTouch.json::doubleSelfdestructTouch": [
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "return0.json::return0": [
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
    "ABAcalls2.json::ABAcalls2": [
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
    "suicideSendEtherToMe.json::suicideSendEtherToMe": [
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
    "CallRecursiveBomb2.json::CallRecursiveBomb2": [
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
    "balanceInputAddressTooBig.json::balanceInputAddressTooBig": [
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
    "callValue.json::callValue": [
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
    "CallRecursiveBombLog2.json::CallRecursiveBombLog2": [
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
    "CalltoReturn2.json::CalltoReturn2": [
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
    "CallToNameRegistratorOutOfGas.json::CallToNameRegistratorOutOfGas": [
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
    "extcodecopy.json::extcodecopy": [
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
    "suicideOrigin.json::suicideOrigin": [
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
    "ABAcallsSuicide0.json::ABAcallsSuicide0": [
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
    "Call10.json::Call10": [
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
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
    ],
    "currentAccountBalance.json::currentAccountBalance": [
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
    "suicideCallerAddresTooBigLeft.json::suicideCallerAddresTooBigLeft": [
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
    "suicideCaller.json::suicideCaller": [
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
Count :: 23
{
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "London | 0 | ExitCode { value: 38 }",
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "CallToReturn1ForDynamicJump0.json::CallToReturn1ForDynamicJump0": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
    "callcodeToReturn1.json::callcodeToReturn1": [
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
    "callcodeToNameRegistratorAddresTooBigRight.json::callcodeToNameRegistratorAddresTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "callcodeToNameRegistratorAddresTooBigLeft.json::callcodeToNameRegistratorAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
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
    "CallToNameRegistratorZeorSizeMemExpansion.json::CallToNameRegistratorZeorSizeMemExpansion": [
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
    "callcodeTo0.json::callcodeTo0": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "createWithInvalidOpcode.json::createWithInvalidOpcode": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallRecursiveBomb3.json::CallRecursiveBomb3": [
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
    "CallToNameRegistratorTooMuchMemory0.json::CallToNameRegistratorTooMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorAddressTooBigRight.json::CallToNameRegistratorAddressTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorZeroMem.json::createNameRegistratorZeroMem": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistrator0.json::callcodeToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "CallToReturn1ForDynamicJump1.json::CallToReturn1ForDynamicJump1": [
        "Istanbul | 0 | ExitCode { value: 39 }",
        "Berlin | 0 | ExitCode { value: 39 }",
        "London | 0 | ExitCode { value: 39 }",
        "Merge | 0 | ExitCode { value: 39 }",
    ],
    "createNameRegistratorZeroMemExpansion.json::createNameRegistratorZeroMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "testRandomTest.json::testRandomTest": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
}
=== SKIP Status ===
None
=== End ===
```