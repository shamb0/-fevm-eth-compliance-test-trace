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

* Following use-cases are failed, when executed with test vector `transaction.gasLimit`.

> Hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION`, ExitCode::35

| Test ID | Use-Case |
| --- | --- |
| TID-49-14 | callcodeToReturn1 |

> Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| TID-49-17 | CallRecursiveBomb0_OOG_atMaxCallDepth |

* Hit with error `SYS_OUT_OF_GAS`(ExitCode::7)

| Test ID | Use-Case |
| --- | --- |
| TID-49-35 | CallToReturn1ForDynamicJump0 |
| TID-49-42 | createNameRegistratorOutOfMemoryBonds0 |
| TID-49-59 | suicideCaller |
| TID-49-36 | CallToReturn1ForDynamicJump1 |
| TID-49-65 | suicideSendEtherToMe |
| TID-49-39 | CreateHashCollision |
| TID-49-31 | CallToNameRegistratorTooMuchMemory1 |
| TID-49-25 | CallToNameRegistratorAddressTooBigRight |
| TID-49-33 | CallToNameRegistratorZeorSizeMemExpansion |
| TID-49-30 | CallToNameRegistratorTooMuchMemory0 |
| TID-49-32 | CallToNameRegistratorTooMuchMemory2 |
| TID-49-34 | CallToReturn1 |
| TID-49-54 | PostToReturn1 |
| TID-49-09 | callcodeTo0 |
| TID-49-48 | createWithInvalidOpcode |
| TID-49-57 | return2 |
| TID-49-46 | createNameRegistratorZeroMem2 |
| TID-49-37 | CalltoReturn2 |
| TID-49-01 | ABAcalls0 |
| TID-49-26 | CallToNameRegistratorMemOOGAndInsufficientBalance |
| TID-49-04 | ABAcalls3 |
| TID-49-13 | callcodeToNameRegistratorZeroMemExpanion |
| TID-49-45 | createNameRegistratorZeroMem |
| TID-49-58 | suicideAddress |
| TID-49-60 | suicideCallerAddresTooBigLeft |
| TID-49-61 | suicideCallerAddresTooBigRight |
| TID-49-63 | suicideOrigin |
| TID-49-62 | suicideNotExistingAccount |
| TID-49-44 | createNameRegistratorValueTooHigh |
| TID-49-18 | CallRecursiveBomb1 |
| | CallToNameRegistratorNotMuchMemory0 |
| | createNameRegistrator |
| | CallToNameRegistrator0 |
| | createNameRegistratorOutOfMemoryBonds1 |
| | createNameRegistratorZeroMemExpansion |
| | suicideSendEtherPostDeath |
| | balanceInputAddressTooBig |
| | testRandomTest |
| | CallToNameRegistratorAddressTooBigLeft |
| | CallToNameRegistratorOutOfGas |
| | return0 |
| | createNameRegistratorOOG_MemExpansionOOV |
| | CallToNameRegistratorNotMuchMemory1 |
| | callcodeToNameRegistrator0 |
| | return1 |
| | CallRecursiveBomb3 |
| | TestNameRegistrator |
| | callcodeToNameRegistratorAddresTooBigLeft |
| | CallRecursiveBomb2 |
| | callcodeToNameRegistratorAddresTooBigRight |

> Execution Trace

```
2023-02-06T01:26:57.545131Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stSystemOperationsTest", Total Files :: 67
2023-02-06T01:26:57.545409Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T01:26:57.660095Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:57.660247Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:57.660251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:57.660310Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:57.660313Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:57.660377Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:57.660453Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:57.660456Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Istanbul::0
2023-02-06T01:26:57.660460Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T01:26:57.660463Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:57.998025Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T01:26:57.998046Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:26:57.998053Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:26:57.998068Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:26:57.998078Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Berlin::0
2023-02-06T01:26:57.998080Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T01:26:57.998083Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:57.998201Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T01:26:57.998207Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:26:57.998211Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:26:57.998222Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:26:57.998225Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::London::0
2023-02-06T01:26:57.998227Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T01:26:57.998229Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:57.998302Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T01:26:57.998308Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:26:57.998311Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:26:57.998321Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:26:57.998324Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls0"::Merge::0
2023-02-06T01:26:57.998326Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls0.json"
2023-02-06T01:26:57.998329Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:57.998403Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls0"
2023-02-06T01:26:57.998409Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:26:57.998412Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:26:57.999651Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-02-06T01:26:57.999687Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T01:26:58.067210Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:58.067318Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.067322Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:58.067374Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.067377Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:58.067435Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.067508Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:58.067511Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Istanbul::0
2023-02-06T01:26:58.067515Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T01:26:58.067517Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.420876Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T01:26:58.420901Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 315982640,
    events_root: None,
}
2023-02-06T01:26:58.421557Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:26:58.421562Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Berlin::0
2023-02-06T01:26:58.421565Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T01:26:58.421567Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.437365Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T01:26:58.437400Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 262203286,
    events_root: None,
}
2023-02-06T01:26:58.437911Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:26:58.437916Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::London::0
2023-02-06T01:26:58.437918Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T01:26:58.437921Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.454179Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T01:26:58.454212Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 262203286,
    events_root: None,
}
2023-02-06T01:26:58.454721Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:26:58.454726Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls1"::Merge::0
2023-02-06T01:26:58.454728Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls1.json"
2023-02-06T01:26:58.454731Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.470739Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls1"
2023-02-06T01:26:58.470771Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 262203286,
    events_root: None,
}
2023-02-06T01:26:58.474064Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-02-06T01:26:58.474104Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T01:26:58.506600Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:58.506706Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.506710Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:58.506765Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.506768Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:58.506827Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.506901Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:58.506905Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Istanbul::0
2023-02-06T01:26:58.506908Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T01:26:58.506911Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.878905Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T01:26:58.878922Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 427682923,
    events_root: None,
}
2023-02-06T01:26:58.879514Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:26:58.879519Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Berlin::0
2023-02-06T01:26:58.879523Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T01:26:58.879525Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.899157Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T01:26:58.899176Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 427728012,
    events_root: None,
}
2023-02-06T01:26:58.899791Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:26:58.899796Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::London::0
2023-02-06T01:26:58.899800Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T01:26:58.899802Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.919798Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T01:26:58.919819Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 427728012,
    events_root: None,
}
2023-02-06T01:26:58.920444Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:26:58.920450Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls2"::Merge::0
2023-02-06T01:26:58.920453Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls2.json"
2023-02-06T01:26:58.920456Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:58.939903Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls2"
2023-02-06T01:26:58.939921Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 427728012,
    events_root: None,
}
2023-02-06T01:26:58.943418Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-02-06T01:26:58.943450Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T01:26:58.971420Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:58.971524Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.971527Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:58.971587Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.971590Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:58.971649Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:58.971731Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:58.971734Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Istanbul::0
2023-02-06T01:26:58.971738Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T01:26:58.971740Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.326359Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T01:26:59.326378Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:26:59.326383Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
                    source: 401,
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
                    source: 401,
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
2023-02-06T01:26:59.326422Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:26:59.326426Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Berlin::0
2023-02-06T01:26:59.326429Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T01:26:59.326431Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.326832Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T01:26:59.326840Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:26:59.326844Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
                    source: 401,
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
                    source: 401,
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
2023-02-06T01:26:59.326876Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:26:59.326879Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::London::0
2023-02-06T01:26:59.326881Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T01:26:59.326883Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.327282Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T01:26:59.327289Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:26:59.327293Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
                    source: 401,
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
                    source: 401,
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
2023-02-06T01:26:59.327324Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:26:59.327327Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcalls3"::Merge::0
2023-02-06T01:26:59.327330Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcalls3.json"
2023-02-06T01:26:59.327332Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.327726Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcalls3"
2023-02-06T01:26:59.327733Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:26:59.327736Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
                    source: 401,
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
                    source: 401,
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
2023-02-06T01:26:59.328842Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-02-06T01:26:59.328866Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T01:26:59.353717Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:59.353822Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.353826Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:59.353879Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.353882Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:59.353941Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.354019Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:59.354023Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Istanbul::0
2023-02-06T01:26:59.354027Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T01:26:59.354030Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.711439Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T01:26:59.711457Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631129,
    events_root: None,
}
2023-02-06T01:26:59.711466Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:26:59.711469Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Berlin::0
2023-02-06T01:26:59.711471Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T01:26:59.711473Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.711553Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T01:26:59.711558Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:26:59.711562Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:26:59.711564Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::London::0
2023-02-06T01:26:59.711566Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T01:26:59.711568Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.711630Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T01:26:59.711635Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:26:59.711639Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:26:59.711641Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide0"::Merge::0
2023-02-06T01:26:59.711643Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide0.json"
2023-02-06T01:26:59.711644Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:26:59.711706Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide0"
2023-02-06T01:26:59.711710Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:26:59.712812Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-02-06T01:26:59.712832Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T01:26:59.766249Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:26:59.766372Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.766377Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:26:59.766446Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.766450Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:26:59.766510Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:26:59.766586Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:26:59.766589Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::0
2023-02-06T01:26:59.766592Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:26:59.766594Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.119427Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.119446Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T01:27:00.119455Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 1
2023-02-06T01:27:00.119459Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Istanbul::1
2023-02-06T01:27:00.119460Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.119462Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.119586Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.119593Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T01:27:00.119599Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:00.119601Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::0
2023-02-06T01:27:00.119603Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.119604Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.119729Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.119735Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T01:27:00.119741Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 1
2023-02-06T01:27:00.119743Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Berlin::1
2023-02-06T01:27:00.119745Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.119747Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.119876Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.119882Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T01:27:00.119887Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:00.119889Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::0
2023-02-06T01:27:00.119891Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.119893Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.120006Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.120012Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T01:27:00.120017Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 1
2023-02-06T01:27:00.120020Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::London::1
2023-02-06T01:27:00.120021Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.120023Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.120134Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.120140Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T01:27:00.120145Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:00.120148Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::0
2023-02-06T01:27:00.120149Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.120151Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.120263Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.120269Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-02-06T01:27:00.120274Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 1
2023-02-06T01:27:00.120276Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ABAcallsSuicide1"::Merge::1
2023-02-06T01:27:00.120278Z  INFO evm_eth_compliance::statetest::executor: Path : "ABAcallsSuicide1.json"
2023-02-06T01:27:00.120280Z  INFO evm_eth_compliance::statetest::executor: TX len : 32
2023-02-06T01:27:00.120423Z  INFO evm_eth_compliance::statetest::executor: UC : "ABAcallsSuicide1"
2023-02-06T01:27:00.120430Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-02-06T01:27:00.121798Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-02-06T01:27:00.121821Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T01:27:00.153251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:00.153359Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.153363Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:00.153411Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.153414Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:00.153466Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.153539Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:00.153542Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Istanbul::0
2023-02-06T01:27:00.153545Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T01:27:00.153547Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.491381Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T01:27:00.491399Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25719303,
    events_root: None,
}
2023-02-06T01:27:00.491435Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:00.491439Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Berlin::0
2023-02-06T01:27:00.491441Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T01:27:00.491443Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.492700Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T01:27:00.492707Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T01:27:00.492738Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:00.492741Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::London::0
2023-02-06T01:27:00.492742Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T01:27:00.492744Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.494002Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T01:27:00.494009Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T01:27:00.494040Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:00.494042Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "Call10"::Merge::0
2023-02-06T01:27:00.494044Z  INFO evm_eth_compliance::statetest::executor: Path : "Call10.json"
2023-02-06T01:27:00.494046Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.495287Z  INFO evm_eth_compliance::statetest::executor: UC : "Call10"
2023-02-06T01:27:00.495294Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-02-06T01:27:00.496609Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-02-06T01:27:00.496637Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T01:27:00.522345Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:00.522443Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.522447Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:00.522497Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.522499Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:00.522555Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.522625Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:00.522629Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Istanbul::0
2023-02-06T01:27:00.522632Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T01:27:00.522634Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.911868Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T01:27:00.911886Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:00.912008Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:00.912011Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Berlin::0
2023-02-06T01:27:00.912014Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T01:27:00.912016Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.916397Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T01:27:00.916410Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:00.916534Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:00.916538Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::London::0
2023-02-06T01:27:00.916539Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T01:27:00.916541Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.920721Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T01:27:00.920730Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:00.920850Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:00.920852Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0"::Merge::0
2023-02-06T01:27:00.920854Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0.json"
2023-02-06T01:27:00.920856Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:00.924919Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0"
2023-02-06T01:27:00.924927Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:00.926619Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-02-06T01:27:00.926645Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:00.976272Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:00.976378Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.976381Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:00.976436Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:00.976508Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:00.976511Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Istanbul::0
2023-02-06T01:27:00.976514Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:00.976516Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.417030Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T01:27:01.417050Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1420215981,
    events_root: None,
}
2023-02-06T01:27:01.418939Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:01.418948Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Berlin::0
2023-02-06T01:27:01.418951Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:01.418953Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.494553Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T01:27:01.494576Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1809992219,
    events_root: None,
}
2023-02-06T01:27:01.496629Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:01.496640Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::London::0
2023-02-06T01:27:01.496643Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:01.496645Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.547607Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T01:27:01.547627Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1218382046,
    events_root: None,
}
2023-02-06T01:27:01.549379Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:01.549386Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Merge::0
2023-02-06T01:27:01.549388Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:01.549391Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.549679Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb0_OOG_atMaxCallDepth"
2023-02-06T01:27:01.549686Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 2293561,
    events_root: None,
}
2023-02-06T01:27:01.549690Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:01.555133Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-02-06T01:27:01.555169Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T01:27:01.587218Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:01.587318Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:01.587321Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:01.587375Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:01.587447Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:01.587450Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Istanbul::0
2023-02-06T01:27:01.587452Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T01:27:01.587454Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.958485Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T01:27:01.958505Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622100,
    events_root: None,
}
2023-02-06T01:27:01.958510Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:01.958568Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:01.958571Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Berlin::0
2023-02-06T01:27:01.958573Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T01:27:01.958575Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.959450Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T01:27:01.959457Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622100,
    events_root: None,
}
2023-02-06T01:27:01.959461Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:01.959515Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:01.959518Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::London::0
2023-02-06T01:27:01.959519Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T01:27:01.959521Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.960373Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T01:27:01.960379Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622100,
    events_root: None,
}
2023-02-06T01:27:01.960382Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:01.960436Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:01.960439Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb1"::Merge::0
2023-02-06T01:27:01.960440Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb1.json"
2023-02-06T01:27:01.960442Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:01.961296Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb1"
2023-02-06T01:27:01.961302Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622100,
    events_root: None,
}
2023-02-06T01:27:01.961306Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:01.962294Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-02-06T01:27:01.962315Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T01:27:01.996907Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:01.997013Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:01.997017Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:01.997070Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:01.997142Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:01.997145Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Istanbul::0
2023-02-06T01:27:01.997148Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T01:27:01.997150Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.351697Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T01:27:02.351718Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622099,
    events_root: None,
}
2023-02-06T01:27:02.351723Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.351780Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:02.351784Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Berlin::0
2023-02-06T01:27:02.351787Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T01:27:02.351788Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.352647Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T01:27:02.352654Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622099,
    events_root: None,
}
2023-02-06T01:27:02.352658Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.352714Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:02.352717Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::London::0
2023-02-06T01:27:02.352720Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T01:27:02.352723Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.353613Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T01:27:02.353621Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622099,
    events_root: None,
}
2023-02-06T01:27:02.353626Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.353684Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:02.353687Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb2"::Merge::0
2023-02-06T01:27:02.353690Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb2.json"
2023-02-06T01:27:02.353692Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.354559Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb2"
2023-02-06T01:27:02.354565Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 20622099,
    events_root: None,
}
2023-02-06T01:27:02.354569Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.355352Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-02-06T01:27:02.355373Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T01:27:02.379757Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:02.379863Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:02.379867Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:02.379920Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:02.379992Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:02.379995Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Istanbul::0
2023-02-06T01:27:02.379997Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T01:27:02.379999Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.722643Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T01:27:02.722664Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:02.722669Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.722681Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:02.722684Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Berlin::0
2023-02-06T01:27:02.722686Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T01:27:02.722687Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.722776Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T01:27:02.722781Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:02.722784Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.722792Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:02.722794Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::London::0
2023-02-06T01:27:02.722795Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T01:27:02.722797Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.722860Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T01:27:02.722865Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:02.722868Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.722875Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:02.722877Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBomb3"::Merge::0
2023-02-06T01:27:02.722878Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBomb3.json"
2023-02-06T01:27:02.722880Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:02.722940Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBomb3"
2023-02-06T01:27:02.722945Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:02.722947Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:02.723555Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-02-06T01:27:02.723574Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T01:27:02.756228Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:02.756327Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:02.756330Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:02.756381Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:02.756383Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:02.756438Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:02.756507Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:02.756511Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Istanbul::0
2023-02-06T01:27:02.756514Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T01:27:02.756516Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.101166Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T01:27:03.101187Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.101325Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:03.101329Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Berlin::0
2023-02-06T01:27:03.101331Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T01:27:03.101333Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.105794Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T01:27:03.105802Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.105922Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:03.105925Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::London::0
2023-02-06T01:27:03.105927Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T01:27:03.105929Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.110228Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T01:27:03.110235Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.110354Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:03.110357Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog"::Merge::0
2023-02-06T01:27:03.110359Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog.json"
2023-02-06T01:27:03.110361Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.114633Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog"
2023-02-06T01:27:03.114640Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.115953Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-02-06T01:27:03.115975Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T01:27:03.141681Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:03.141789Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.141793Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:03.141846Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.141849Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:03.141925Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.142026Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:03.142032Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Istanbul::0
2023-02-06T01:27:03.142036Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T01:27:03.142039Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.480615Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T01:27:03.480634Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.480753Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:03.480758Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Berlin::0
2023-02-06T01:27:03.480759Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T01:27:03.480762Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.484834Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T01:27:03.484841Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.484958Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:03.484961Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::London::0
2023-02-06T01:27:03.484963Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T01:27:03.484965Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.488989Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T01:27:03.488997Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.489114Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:03.489116Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallRecursiveBombLog2"::Merge::0
2023-02-06T01:27:03.489118Z  INFO evm_eth_compliance::statetest::executor: Path : "CallRecursiveBombLog2.json"
2023-02-06T01:27:03.489120Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.493163Z  INFO evm_eth_compliance::statetest::executor: UC : "CallRecursiveBombLog2"
2023-02-06T01:27:03.493171Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-02-06T01:27:03.494517Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-02-06T01:27:03.494556Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T01:27:03.518442Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:03.518545Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.518548Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:03.518598Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.518600Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:03.518656Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.518726Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:03.518729Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Istanbul::0
2023-02-06T01:27:03.518732Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T01:27:03.518734Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.856913Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T01:27:03.856934Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:03.856939Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:03.856951Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:03.856955Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Berlin::0
2023-02-06T01:27:03.856957Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T01:27:03.856960Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.856987Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T01:27:03.856991Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:03.856995Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:03.857004Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:03.857006Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::London::0
2023-02-06T01:27:03.857009Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T01:27:03.857012Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.857020Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T01:27:03.857024Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:03.857027Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:03.857035Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:03.857038Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistrator0"::Merge::0
2023-02-06T01:27:03.857040Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistrator0.json"
2023-02-06T01:27:03.857043Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:03.857051Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistrator0"
2023-02-06T01:27:03.857054Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:03.857058Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:03.857794Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-02-06T01:27:03.857815Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:03.908585Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:03.908689Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.908693Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:03.908743Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.908745Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:03.908801Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:03.908872Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:03.908874Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Istanbul::0
2023-02-06T01:27:03.908878Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:03.908880Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.253633Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T01:27:04.253653Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.253659Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.253675Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:04.253678Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Berlin::0
2023-02-06T01:27:04.253681Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:04.253683Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.253709Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T01:27:04.253712Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.253715Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.253721Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:04.253723Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::London::0
2023-02-06T01:27:04.253725Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:04.253727Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.253733Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T01:27:04.253736Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.253738Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.253744Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:04.253746Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Merge::0
2023-02-06T01:27:04.253747Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:04.253749Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.253755Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigLeft"
2023-02-06T01:27:04.253758Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.253760Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.254359Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-02-06T01:27:04.254382Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.278719Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:04.278817Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.278821Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:04.278871Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.278873Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:04.278930Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.279000Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:04.279003Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Istanbul::0
2023-02-06T01:27:04.279006Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.279009Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.623572Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T01:27:04.623594Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.623600Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.623613Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:04.623617Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Berlin::0
2023-02-06T01:27:04.623620Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.623622Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.623649Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T01:27:04.623653Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.623658Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.623667Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:04.623669Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::London::0
2023-02-06T01:27:04.623672Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.623675Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.623684Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T01:27:04.623689Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.623692Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.623701Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:04.623703Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Merge::0
2023-02-06T01:27:04.623706Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.623709Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:04.623719Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorAddressTooBigRight"
2023-02-06T01:27:04.623723Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:04.623726Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:04.624293Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-02-06T01:27:04.624316Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:04.681168Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:04.681280Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.681283Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:04.681337Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.681339Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:04.681414Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:04.681513Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:04.681517Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Istanbul::0
2023-02-06T01:27:04.681522Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:04.681525Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.024563Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T01:27:05.024585Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.024590Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.024602Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:05.024606Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Berlin::0
2023-02-06T01:27:05.024608Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:05.024610Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.024635Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T01:27:05.024639Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.024641Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.024648Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:05.024649Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::London::0
2023-02-06T01:27:05.024651Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:05.024653Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.024660Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T01:27:05.024663Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.024665Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.024671Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:05.024673Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Merge::0
2023-02-06T01:27:05.024675Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:05.024677Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.024682Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorMemOOGAndInsufficientBalance"
2023-02-06T01:27:05.024685Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.024688Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.025321Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-02-06T01:27:05.025344Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.077548Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:05.077656Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.077660Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:05.077715Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.077717Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:05.077773Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.077844Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:05.077846Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Istanbul::0
2023-02-06T01:27:05.077850Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.077852Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.410029Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T01:27:05.410053Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.410058Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.410071Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:05.410075Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Berlin::0
2023-02-06T01:27:05.410078Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.410081Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.410105Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T01:27:05.410110Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.410113Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.410122Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:05.410125Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::London::0
2023-02-06T01:27:05.410127Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.410130Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.410139Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T01:27:05.410143Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.410146Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.410155Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:05.410157Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Merge::0
2023-02-06T01:27:05.410159Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.410162Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.410171Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory0"
2023-02-06T01:27:05.410175Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:05.410178Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.410798Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-02-06T01:27:05.410826Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.435153Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:05.435263Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.435267Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:05.435321Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.435325Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:05.435384Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.435456Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:05.435461Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Istanbul::0
2023-02-06T01:27:05.435465Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.435469Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.782592Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T01:27:05.782616Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 290000,
    events_root: None,
}
2023-02-06T01:27:05.782622Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.782637Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:05.782642Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Berlin::0
2023-02-06T01:27:05.782644Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.782649Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.782679Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T01:27:05.782684Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 290000,
    events_root: None,
}
2023-02-06T01:27:05.782687Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.782695Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:05.782698Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::London::0
2023-02-06T01:27:05.782700Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.782703Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.782712Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T01:27:05.782715Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 290000,
    events_root: None,
}
2023-02-06T01:27:05.782718Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.782724Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:05.782726Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Merge::0
2023-02-06T01:27:05.782727Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.782729Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:05.782734Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorNotMuchMemory1"
2023-02-06T01:27:05.782737Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 290000,
    events_root: None,
}
2023-02-06T01:27:05.782739Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:05.783560Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-02-06T01:27:05.783581Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:05.808297Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:05.808399Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.808402Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:05.808452Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.808454Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:05.808510Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:05.808580Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:05.808583Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Istanbul::0
2023-02-06T01:27:05.808586Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:05.808588Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.149352Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T01:27:06.149374Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.149380Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.149392Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:06.149396Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Berlin::0
2023-02-06T01:27:06.149397Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:06.149401Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.149423Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T01:27:06.149426Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.149429Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.149435Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:06.149437Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::London::0
2023-02-06T01:27:06.149440Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:06.149442Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.149448Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T01:27:06.149451Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.149453Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.149459Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:06.149460Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorOutOfGas"::Merge::0
2023-02-06T01:27:06.149462Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:06.149464Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.149470Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorOutOfGas"
2023-02-06T01:27:06.149473Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.149476Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.150057Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-02-06T01:27:06.150087Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.174285Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:06.174386Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.174390Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:06.174441Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.174443Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:06.174500Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.174572Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:06.174575Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Istanbul::0
2023-02-06T01:27:06.174578Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.174580Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.507724Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T01:27:06.507747Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.507753Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.507764Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:06.507767Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Berlin::0
2023-02-06T01:27:06.507769Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.507771Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.507795Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T01:27:06.507798Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.507801Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.507807Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:06.507809Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::London::0
2023-02-06T01:27:06.507811Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.507813Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.507819Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T01:27:06.507822Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.507824Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.507830Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:06.507832Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Merge::0
2023-02-06T01:27:06.507833Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.507835Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.507840Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory0"
2023-02-06T01:27:06.507843Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.507845Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.508394Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-02-06T01:27:06.508421Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.576360Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:06.576460Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.576463Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:06.576513Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.576515Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:06.576591Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.576700Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:06.576706Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Istanbul::0
2023-02-06T01:27:06.576710Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.576714Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.911737Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T01:27:06.911760Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.911766Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.911778Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:06.911781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Berlin::0
2023-02-06T01:27:06.911784Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.911786Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.911810Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T01:27:06.911813Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.911816Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.911822Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:06.911824Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::London::0
2023-02-06T01:27:06.911825Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.911827Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.911833Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T01:27:06.911836Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.911838Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.911844Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:06.911846Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Merge::0
2023-02-06T01:27:06.911847Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.911849Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:06.911854Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory1"
2023-02-06T01:27:06.911857Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:06.911859Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:06.912429Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-02-06T01:27:06.912456Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:06.939158Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:06.939267Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.939270Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:06.939327Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.939330Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:06.939405Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:06.939498Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:06.939503Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Istanbul::0
2023-02-06T01:27:06.939507Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:06.939509Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.292201Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T01:27:07.292222Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:07.292228Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.292239Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:07.292243Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Berlin::0
2023-02-06T01:27:07.292246Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:07.292247Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.292272Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T01:27:07.292276Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:07.292278Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.292285Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:07.292287Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::London::0
2023-02-06T01:27:07.292289Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:07.292291Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.292297Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T01:27:07.292300Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:07.292303Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.292308Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:07.292310Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Merge::0
2023-02-06T01:27:07.292312Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:07.292313Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.292318Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorTooMuchMemory2"
2023-02-06T01:27:07.292321Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:07.292324Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.292901Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-02-06T01:27:07.292923Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.319364Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:07.319468Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.319472Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:07.319525Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.319527Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:07.319587Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.319658Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:07.319661Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T01:27:07.319665Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.319667Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659614Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659636Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T01:27:07.659641Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.659652Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:07.659657Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-02-06T01:27:07.659659Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659661Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659667Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659671Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:07.659674Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:07.659676Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:07.659678Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T01:27:07.659680Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659682Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659703Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659706Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T01:27:07.659708Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.659714Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:07.659716Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-02-06T01:27:07.659719Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659721Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659722Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659725Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:07.659727Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:07.659729Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:07.659731Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T01:27:07.659733Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659735Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659741Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659743Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T01:27:07.659745Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.659751Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:07.659752Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-02-06T01:27:07.659754Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659756Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659758Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659761Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:07.659763Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:07.659765Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:07.659766Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T01:27:07.659769Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659770Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659777Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659780Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 500000,
    events_root: None,
}
2023-02-06T01:27:07.659783Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:07.659788Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:07.659790Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-02-06T01:27:07.659792Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.659793Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:07.659795Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToNameRegistratorZeorSizeMemExpansion"
2023-02-06T01:27:07.659798Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:07.659800Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:07.660380Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-02-06T01:27:07.660402Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T01:27:07.684508Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:07.684613Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.684617Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:07.684667Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.684669Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:07.684726Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:07.684796Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:07.684798Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Istanbul::0
2023-02-06T01:27:07.684802Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T01:27:07.684804Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.015553Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T01:27:08.015574Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.015579Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.015591Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:08.015594Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Berlin::0
2023-02-06T01:27:08.015596Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T01:27:08.015598Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.015624Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T01:27:08.015627Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.015630Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.015636Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:08.015638Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::London::0
2023-02-06T01:27:08.015640Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T01:27:08.015642Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.015647Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T01:27:08.015650Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.015652Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.015658Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:08.015660Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1"::Merge::0
2023-02-06T01:27:08.015661Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1.json"
2023-02-06T01:27:08.015663Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.015668Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1"
2023-02-06T01:27:08.015671Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.015673Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.016274Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-02-06T01:27:08.016294Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.040516Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:08.040617Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.040620Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:08.040671Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.040673Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:08.040728Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.040798Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:08.040800Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Istanbul::0
2023-02-06T01:27:08.040804Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.040806Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.382909Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T01:27:08.382929Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.382934Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.382945Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:08.382949Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Berlin::0
2023-02-06T01:27:08.382951Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.382953Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.382975Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T01:27:08.382978Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.382981Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.382987Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:08.382988Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::London::0
2023-02-06T01:27:08.382990Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.382992Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.382997Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T01:27:08.383000Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.383002Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.383008Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:08.383009Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump0"::Merge::0
2023-02-06T01:27:08.383011Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.383013Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.383019Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump0"
2023-02-06T01:27:08.383022Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.383024Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.383557Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-02-06T01:27:08.383583Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.407745Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:08.407844Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.407848Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:08.407899Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.407901Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:08.407957Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.408027Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:08.408030Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Istanbul::0
2023-02-06T01:27:08.408033Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.408036Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.744096Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T01:27:08.744119Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.744126Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.744140Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:08.744144Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Berlin::0
2023-02-06T01:27:08.744149Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.744151Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.744180Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T01:27:08.744184Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.744188Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.744195Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:08.744198Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::London::0
2023-02-06T01:27:08.744200Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.744202Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.744211Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T01:27:08.744214Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.744217Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.744225Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:08.744227Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CallToReturn1ForDynamicJump1"::Merge::0
2023-02-06T01:27:08.744229Z  INFO evm_eth_compliance::statetest::executor: Path : "CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.744233Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:08.744241Z  INFO evm_eth_compliance::statetest::executor: UC : "CallToReturn1ForDynamicJump1"
2023-02-06T01:27:08.744246Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:08.744249Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:08.744914Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-02-06T01:27:08.744945Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T01:27:08.769852Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:08.769948Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.769952Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:08.770004Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.770006Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:08.770062Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:08.770132Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:08.770135Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Istanbul::0
2023-02-06T01:27:08.770138Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T01:27:08.770140Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:09.135353Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T01:27:09.135374Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:09.135382Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.135394Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:09.135398Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Berlin::0
2023-02-06T01:27:09.135400Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T01:27:09.135401Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:09.135429Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T01:27:09.135432Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:09.135435Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.135442Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:09.135443Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::London::0
2023-02-06T01:27:09.135445Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T01:27:09.135446Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:09.135452Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T01:27:09.135455Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:09.135457Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.135464Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:09.135466Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CalltoReturn2"::Merge::0
2023-02-06T01:27:09.135467Z  INFO evm_eth_compliance::statetest::executor: Path : "CalltoReturn2.json"
2023-02-06T01:27:09.135469Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:09.135474Z  INFO evm_eth_compliance::statetest::executor: UC : "CalltoReturn2"
2023-02-06T01:27:09.135477Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:09.135479Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.136078Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-02-06T01:27:09.136098Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T01:27:09.160394Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:09.160497Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.160500Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:09.160554Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.160556Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:09.160615Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.160685Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:09.160688Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Istanbul::0
2023-02-06T01:27:09.160691Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T01:27:09.160694Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:09.609944Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T01:27:09.609964Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3909237,
    events_root: None,
}
2023-02-06T01:27:09.609979Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:09.609982Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Berlin::0
2023-02-06T01:27:09.609984Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T01:27:09.609986Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-06T01:27:09.772954Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T01:27:09.772968Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:27:09.772975Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.773001Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:09.773004Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::London::0
2023-02-06T01:27:09.773006Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T01:27:09.773008Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-06T01:27:09.773577Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T01:27:09.773585Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:27:09.773588Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.773606Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:09.773610Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "CreateHashCollision"::Merge::0
2023-02-06T01:27:09.773612Z  INFO evm_eth_compliance::statetest::executor: Path : "CreateHashCollision.json"
2023-02-06T01:27:09.773613Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-06T01:27:09.774045Z  INFO evm_eth_compliance::statetest::executor: UC : "CreateHashCollision"
2023-02-06T01:27:09.774051Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-06T01:27:09.774055Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:09.775022Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-02-06T01:27:09.775045Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T01:27:09.800246Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:09.800353Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.800356Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:09.800409Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.800411Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:09.800470Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:09.800541Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:09.800544Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Istanbul::0
2023-02-06T01:27:09.800547Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T01:27:09.800549Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.139512Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T01:27:10.139535Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.139540Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.139552Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:10.139556Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Berlin::0
2023-02-06T01:27:10.139557Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T01:27:10.139559Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.139584Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T01:27:10.139588Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.139591Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.139597Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:10.139599Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::London::0
2023-02-06T01:27:10.139600Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T01:27:10.139602Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.139608Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T01:27:10.139610Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.139613Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.139619Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:10.139622Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "PostToReturn1"::Merge::0
2023-02-06T01:27:10.139624Z  INFO evm_eth_compliance::statetest::executor: Path : "PostToReturn1.json"
2023-02-06T01:27:10.139626Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.139633Z  INFO evm_eth_compliance::statetest::executor: UC : "PostToReturn1"
2023-02-06T01:27:10.139636Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.139640Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.140392Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-02-06T01:27:10.140413Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T01:27:10.164989Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:10.165089Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.165092Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:10.165147Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.165219Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:10.165223Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Istanbul::0
2023-02-06T01:27:10.165226Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T01:27:10.165228Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T01:27:10.533940Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T01:27:10.533961Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:10.533966Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.533979Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:10.533983Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Berlin::0
2023-02-06T01:27:10.533984Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T01:27:10.533986Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T01:27:10.534072Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T01:27:10.534078Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:10.534081Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.534088Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:10.534090Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::London::0
2023-02-06T01:27:10.534092Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T01:27:10.534094Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T01:27:10.534164Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T01:27:10.534169Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:10.534172Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.534179Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:10.534181Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "TestNameRegistrator"::Merge::0
2023-02-06T01:27:10.534182Z  INFO evm_eth_compliance::statetest::executor: Path : "TestNameRegistrator.json"
2023-02-06T01:27:10.534184Z  INFO evm_eth_compliance::statetest::executor: TX len : 64
2023-02-06T01:27:10.534250Z  INFO evm_eth_compliance::statetest::executor: UC : "TestNameRegistrator"
2023-02-06T01:27:10.534255Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:10.534259Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.534952Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-02-06T01:27:10.534974Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T01:27:10.561969Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:10.562084Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.562088Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:10.562143Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.562218Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:10.562221Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Istanbul::0
2023-02-06T01:27:10.562224Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T01:27:10.562226Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.921110Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T01:27:10.921135Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.921141Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.921152Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:10.921156Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Berlin::0
2023-02-06T01:27:10.921158Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T01:27:10.921160Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.921184Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T01:27:10.921187Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.921190Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.921196Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:10.921198Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::London::0
2023-02-06T01:27:10.921199Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T01:27:10.921201Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.921206Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T01:27:10.921209Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.921211Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.921217Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:10.921218Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "balanceInputAddressTooBig"::Merge::0
2023-02-06T01:27:10.921220Z  INFO evm_eth_compliance::statetest::executor: Path : "balanceInputAddressTooBig.json"
2023-02-06T01:27:10.921221Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:10.921227Z  INFO evm_eth_compliance::statetest::executor: UC : "balanceInputAddressTooBig"
2023-02-06T01:27:10.921229Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:10.921231Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:10.921833Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-02-06T01:27:10.921857Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T01:27:10.945624Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:10.945727Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.945732Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:10.945787Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:10.945859Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:10.945863Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Istanbul::0
2023-02-06T01:27:10.945866Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T01:27:10.945869Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.276563Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T01:27:11.276583Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T01:27:11.276592Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:11.276595Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Berlin::0
2023-02-06T01:27:11.276597Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T01:27:11.276598Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.276699Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T01:27:11.276705Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T01:27:11.276709Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:11.276711Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::London::0
2023-02-06T01:27:11.276713Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T01:27:11.276715Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.276795Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T01:27:11.276800Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T01:27:11.276804Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:11.276806Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callValue"::Merge::0
2023-02-06T01:27:11.276808Z  INFO evm_eth_compliance::statetest::executor: Path : "callValue.json"
2023-02-06T01:27:11.276809Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.276888Z  INFO evm_eth_compliance::statetest::executor: UC : "callValue"
2023-02-06T01:27:11.276893Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-02-06T01:27:11.277536Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-02-06T01:27:11.277561Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T01:27:11.301205Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:11.301307Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:11.301311Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:11.301362Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:11.301430Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:11.301433Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Istanbul::0
2023-02-06T01:27:11.301436Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T01:27:11.301438Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.672721Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T01:27:11.672744Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T01:27:11.672750Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:11.672767Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:11.672772Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Berlin::0
2023-02-06T01:27:11.672775Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T01:27:11.672778Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.672921Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T01:27:11.672929Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T01:27:11.672933Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:11.672945Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:11.672948Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::London::0
2023-02-06T01:27:11.672951Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T01:27:11.672954Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.673078Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T01:27:11.673086Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T01:27:11.673090Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:11.673104Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:11.673106Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeTo0"::Merge::0
2023-02-06T01:27:11.673110Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeTo0.json"
2023-02-06T01:27:11.673112Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:11.673236Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeTo0"
2023-02-06T01:27:11.673243Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-02-06T01:27:11.673247Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:11.674210Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-02-06T01:27:11.674242Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T01:27:11.706983Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:11.707087Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:11.707090Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:11.707140Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:11.707142Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:11.707200Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:11.707270Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:11.707272Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Istanbul::0
2023-02-06T01:27:11.707275Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T01:27:11.707277Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.070475Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T01:27:12.070496Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.070501Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.070512Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:12.070515Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Berlin::0
2023-02-06T01:27:12.070517Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T01:27:12.070519Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.070635Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T01:27:12.070640Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.070644Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.070651Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:12.070653Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::London::0
2023-02-06T01:27:12.070655Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T01:27:12.070657Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.070724Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T01:27:12.070728Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.070731Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.070739Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:12.070741Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistrator0"::Merge::0
2023-02-06T01:27:12.070743Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistrator0.json"
2023-02-06T01:27:12.070745Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.070812Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistrator0"
2023-02-06T01:27:12.070818Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.070821Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.071403Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-02-06T01:27:12.071429Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.095911Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:12.096033Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.096039Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:12.096107Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.096110Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:12.096184Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.096285Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:12.096290Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Istanbul::0
2023-02-06T01:27:12.096294Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.096297Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.431055Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T01:27:12.431080Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.431086Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.431097Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:12.431101Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Berlin::0
2023-02-06T01:27:12.431103Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.431105Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.431193Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T01:27:12.431199Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.431202Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.431209Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:12.431211Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::London::0
2023-02-06T01:27:12.431213Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.431215Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.431282Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T01:27:12.431287Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.431289Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.431296Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:12.431300Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Merge::0
2023-02-06T01:27:12.431302Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.431304Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.431367Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigLeft"
2023-02-06T01:27:12.431372Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.431375Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.432078Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-02-06T01:27:12.432102Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.469051Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:12.469150Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.469153Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:12.469204Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.469207Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:12.469263Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.469352Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:12.469356Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Istanbul::0
2023-02-06T01:27:12.469360Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.469362Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.808256Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T01:27:12.808280Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.808286Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.808298Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:12.808301Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Berlin::0
2023-02-06T01:27:12.808305Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.808307Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.808393Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T01:27:12.808399Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.808403Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.808410Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:12.808412Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::London::0
2023-02-06T01:27:12.808414Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.808416Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.808499Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T01:27:12.808506Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.808509Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.808520Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:12.808522Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Merge::0
2023-02-06T01:27:12.808527Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.808530Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.808614Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorAddresTooBigRight"
2023-02-06T01:27:12.808621Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:12.808625Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:12.809252Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-02-06T01:27:12.809283Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:12.834622Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:12.834726Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.834729Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:12.834781Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.834783Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:12.834842Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:12.834912Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:12.834915Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T01:27:12.834919Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:12.834921Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:12.834924Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:12.834928Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:12.834933Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:12.834936Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:12.834938Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-02-06T01:27:12.834940Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:12.834943Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.176998Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177022Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:13.177028Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.177042Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:13.177046Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T01:27:13.177049Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177052Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177060Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177064Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:13.177068Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:13.177071Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:13.177074Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-02-06T01:27:13.177076Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177079Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177169Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177175Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:13.177179Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.177189Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:13.177192Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T01:27:13.177195Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177199Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177202Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177207Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:13.177210Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:13.177213Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:13.177216Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-02-06T01:27:13.177219Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177221Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177305Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177311Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:13.177315Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.177325Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:13.177328Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T01:27:13.177331Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177334Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177337Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177341Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 0,
    events_root: None,
}
2023-02-06T01:27:13.177344Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
    PreValidation(
        "Out of gas (168899 > 50000)",
    ),
)
2023-02-06T01:27:13.177348Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:13.177350Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-02-06T01:27:13.177353Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.177355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.177432Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToNameRegistratorZeroMemExpanion"
2023-02-06T01:27:13.177438Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:13.177442Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.178094Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-02-06T01:27:13.178121Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T01:27:13.202805Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:13.202913Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.202918Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:13.202977Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.202979Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:13.203043Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.203117Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:13.203120Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Istanbul::0
2023-02-06T01:27:13.203124Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T01:27:13.203127Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.543630Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T01:27:13.543651Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T01:27:13.543657Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.543669Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:13.543673Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Berlin::0
2023-02-06T01:27:13.543674Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T01:27:13.543676Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.543780Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T01:27:13.543786Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T01:27:13.543789Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.543798Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:13.543800Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::London::0
2023-02-06T01:27:13.543801Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T01:27:13.543804Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.543890Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T01:27:13.543896Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T01:27:13.543898Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.543906Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:13.543908Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callcodeToReturn1"::Merge::0
2023-02-06T01:27:13.543910Z  INFO evm_eth_compliance::statetest::executor: Path : "callcodeToReturn1.json"
2023-02-06T01:27:13.543912Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.543996Z  INFO evm_eth_compliance::statetest::executor: UC : "callcodeToReturn1"
2023-02-06T01:27:13.544001Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-02-06T01:27:13.544004Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:13.544605Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-02-06T01:27:13.544633Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T01:27:13.569114Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:13.569213Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.569216Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:13.569267Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.569347Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:13.569350Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Istanbul::0
2023-02-06T01:27:13.569353Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T01:27:13.569355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.901173Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T01:27:13.901194Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2479617,
    events_root: None,
}
2023-02-06T01:27:13.901205Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:13.901209Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Berlin::0
2023-02-06T01:27:13.901210Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T01:27:13.901212Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.901352Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T01:27:13.901358Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T01:27:13.901363Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:13.901365Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::London::0
2023-02-06T01:27:13.901366Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T01:27:13.901368Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.901478Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T01:27:13.901484Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T01:27:13.901488Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:13.901490Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "callerAccountBalance"::Merge::0
2023-02-06T01:27:13.901491Z  INFO evm_eth_compliance::statetest::executor: Path : "callerAccountBalance.json"
2023-02-06T01:27:13.901493Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:13.901584Z  INFO evm_eth_compliance::statetest::executor: UC : "callerAccountBalance"
2023-02-06T01:27:13.901589Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-02-06T01:27:13.902246Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-02-06T01:27:13.902272Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T01:27:13.926565Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:13.926662Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.926665Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:13.926717Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:13.926786Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:13.926789Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Istanbul::0
2023-02-06T01:27:13.926791Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T01:27:13.926793Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.269612Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T01:27:14.269635Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.269640Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.269652Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:14.269656Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Berlin::0
2023-02-06T01:27:14.269658Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T01:27:14.269660Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.269684Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T01:27:14.269687Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.269690Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.269696Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:14.269698Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::London::0
2023-02-06T01:27:14.269700Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T01:27:14.269701Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.269708Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T01:27:14.269710Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.269713Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.269718Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:14.269720Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistrator"::Merge::0
2023-02-06T01:27:14.269722Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistrator.json"
2023-02-06T01:27:14.269723Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.269728Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistrator"
2023-02-06T01:27:14.269731Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.269733Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.270454Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-02-06T01:27:14.270481Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.295365Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:14.295472Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:14.295476Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:14.295532Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:14.295604Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:14.295607Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Istanbul::0
2023-02-06T01:27:14.295610Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.295612Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.644083Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T01:27:14.644104Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.644109Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.644120Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:14.644124Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Berlin::0
2023-02-06T01:27:14.644126Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.644128Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.644151Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T01:27:14.644154Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.644157Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.644164Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:14.644165Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::London::0
2023-02-06T01:27:14.644167Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.644169Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.644175Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T01:27:14.644178Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.644180Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.644186Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:14.644187Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Merge::0
2023-02-06T01:27:14.644189Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.644191Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:14.644196Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOOG_MemExpansionOOV"
2023-02-06T01:27:14.644199Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:14.644201Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:14.644836Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-02-06T01:27:14.644858Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:14.669251Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:14.669360Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:14.669364Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:14.669418Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:14.669492Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:14.669495Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Istanbul::0
2023-02-06T01:27:14.669498Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:14.669500Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.043025Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T01:27:15.043045Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.043050Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.043062Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:15.043065Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Berlin::0
2023-02-06T01:27:15.043067Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:15.043069Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.043092Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T01:27:15.043097Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.043100Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.043106Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:15.043108Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::London::0
2023-02-06T01:27:15.043110Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:15.043112Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.043117Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T01:27:15.043120Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.043122Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.043128Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:15.043130Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Merge::0
2023-02-06T01:27:15.043132Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:15.043133Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.043138Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds0"
2023-02-06T01:27:15.043141Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.043143Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.043750Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-02-06T01:27:15.043779Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.068461Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:15.068561Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.068565Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:15.068627Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.068699Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:15.068702Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Istanbul::0
2023-02-06T01:27:15.068705Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.068707Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.399446Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T01:27:15.399467Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.399473Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.399483Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:15.399487Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Berlin::0
2023-02-06T01:27:15.399489Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.399491Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.399514Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T01:27:15.399517Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.399520Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.399526Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:15.399527Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::London::0
2023-02-06T01:27:15.399529Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.399531Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.399537Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T01:27:15.399539Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.399542Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.399547Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:15.399549Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Merge::0
2023-02-06T01:27:15.399551Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.399552Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.399558Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorOutOfMemoryBonds1"
2023-02-06T01:27:15.399560Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.399564Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.400199Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-02-06T01:27:15.400230Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.425474Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:15.425581Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.425585Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:15.425637Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.425709Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:15.425713Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Istanbul::0
2023-02-06T01:27:15.425716Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.425718Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.768290Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T01:27:15.768310Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.768317Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.768329Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:15.768334Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Berlin::0
2023-02-06T01:27:15.768336Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.768339Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.768376Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T01:27:15.768380Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.768384Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.768393Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:15.768396Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::London::0
2023-02-06T01:27:15.768399Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.768402Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.768412Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T01:27:15.768415Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.768419Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.768427Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:15.768430Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorValueTooHigh"::Merge::0
2023-02-06T01:27:15.768432Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.768435Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:15.768444Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorValueTooHigh"
2023-02-06T01:27:15.768447Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:15.768450Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:15.769131Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-02-06T01:27:15.769157Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T01:27:15.793760Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:15.793878Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.793883Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:15.793940Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:15.794019Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:15.794023Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Istanbul::0
2023-02-06T01:27:15.794027Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T01:27:15.794032Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.131065Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T01:27:16.131088Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.131094Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.131108Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:16.131112Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Berlin::0
2023-02-06T01:27:16.131115Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T01:27:16.131117Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.131146Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T01:27:16.131151Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.131154Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.131164Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:16.131166Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::London::0
2023-02-06T01:27:16.131169Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T01:27:16.131171Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.131181Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T01:27:16.131185Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.131188Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.131196Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:16.131199Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem"::Merge::0
2023-02-06T01:27:16.131201Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem.json"
2023-02-06T01:27:16.131204Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.131214Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem"
2023-02-06T01:27:16.131218Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.131222Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.131951Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-02-06T01:27:16.131977Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.156837Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:16.156942Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.156945Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:16.156999Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.157072Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:16.157075Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Istanbul::0
2023-02-06T01:27:16.157078Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.157079Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.496275Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T01:27:16.496299Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.496304Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.496317Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:16.496321Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Berlin::0
2023-02-06T01:27:16.496323Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.496325Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.496351Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T01:27:16.496354Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.496357Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.496363Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:16.496364Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::London::0
2023-02-06T01:27:16.496366Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.496368Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.496374Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T01:27:16.496377Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.496380Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.496387Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:16.496389Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMem2"::Merge::0
2023-02-06T01:27:16.496392Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.496394Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.496402Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMem2"
2023-02-06T01:27:16.496405Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.496409Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.497213Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-02-06T01:27:16.497239Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.521720Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:16.521822Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.521826Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:16.521879Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.521950Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:16.521953Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Istanbul::0
2023-02-06T01:27:16.521956Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.521958Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.869004Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T01:27:16.869026Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.869031Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.869043Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:16.869047Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Berlin::0
2023-02-06T01:27:16.869049Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.869052Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.869075Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T01:27:16.869078Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.869082Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.869088Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:16.869090Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::London::0
2023-02-06T01:27:16.869091Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.869093Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.869100Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T01:27:16.869103Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.869105Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.869111Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:16.869113Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createNameRegistratorZeroMemExpansion"::Merge::0
2023-02-06T01:27:16.869114Z  INFO evm_eth_compliance::statetest::executor: Path : "createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.869116Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:16.869121Z  INFO evm_eth_compliance::statetest::executor: UC : "createNameRegistratorZeroMemExpansion"
2023-02-06T01:27:16.869124Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:16.869126Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:16.869825Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-02-06T01:27:16.869848Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T01:27:16.903864Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:16.903963Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.903968Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:16.904022Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:16.904093Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:16.904096Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Istanbul::0
2023-02-06T01:27:16.904099Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T01:27:16.904101Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.238037Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T01:27:17.238058Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:17.238063Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:17.238075Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:17.238079Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Berlin::0
2023-02-06T01:27:17.238081Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T01:27:17.238082Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.238106Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T01:27:17.238109Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:17.238112Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:17.238118Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:17.238119Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::London::0
2023-02-06T01:27:17.238121Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T01:27:17.238123Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.238129Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T01:27:17.238132Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:17.238134Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:17.238140Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:17.238141Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "createWithInvalidOpcode"::Merge::0
2023-02-06T01:27:17.238143Z  INFO evm_eth_compliance::statetest::executor: Path : "createWithInvalidOpcode.json"
2023-02-06T01:27:17.238145Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.238150Z  INFO evm_eth_compliance::statetest::executor: UC : "createWithInvalidOpcode"
2023-02-06T01:27:17.238153Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:17.238155Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:17.238791Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-02-06T01:27:17.238811Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T01:27:17.263066Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:17.263164Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.263167Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:17.263220Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.263290Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:17.263293Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Istanbul::0
2023-02-06T01:27:17.263296Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T01:27:17.263298Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.596616Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T01:27:17.596635Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2509963,
    events_root: None,
}
2023-02-06T01:27:17.596645Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:17.596649Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Berlin::0
2023-02-06T01:27:17.596650Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T01:27:17.596652Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.596768Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T01:27:17.596774Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T01:27:17.596779Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:17.596781Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::London::0
2023-02-06T01:27:17.596783Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T01:27:17.596785Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.596878Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T01:27:17.596884Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T01:27:17.596889Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:17.596891Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "currentAccountBalance"::Merge::0
2023-02-06T01:27:17.596893Z  INFO evm_eth_compliance::statetest::executor: Path : "currentAccountBalance.json"
2023-02-06T01:27:17.596895Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.596987Z  INFO evm_eth_compliance::statetest::executor: UC : "currentAccountBalance"
2023-02-06T01:27:17.596992Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-02-06T01:27:17.597616Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-02-06T01:27:17.597644Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T01:27:17.622329Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:17.622432Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.622436Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:17.622489Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.622562Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:17.622565Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Istanbul::0
2023-02-06T01:27:17.622568Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T01:27:17.622570Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.962035Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T01:27:17.962054Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8688838,
    events_root: None,
}
2023-02-06T01:27:17.962066Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:17.962069Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Berlin::0
2023-02-06T01:27:17.962071Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T01:27:17.962073Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.962155Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T01:27:17.962161Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:17.962165Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:17.962167Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::London::0
2023-02-06T01:27:17.962169Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T01:27:17.962171Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.962241Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T01:27:17.962247Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:17.962252Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:17.962254Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest"::Merge::0
2023-02-06T01:27:17.962256Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest.json"
2023-02-06T01:27:17.962259Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:17.962343Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest"
2023-02-06T01:27:17.962349Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:17.963026Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-02-06T01:27:17.963050Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T01:27:17.988366Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:17.988470Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.988474Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:17.988526Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:17.988598Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:17.988603Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Istanbul::0
2023-02-06T01:27:17.988605Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T01:27:17.988607Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.337480Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T01:27:18.337501Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7674311,
    events_root: None,
}
2023-02-06T01:27:18.337514Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:18.337517Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Berlin::0
2023-02-06T01:27:18.337519Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T01:27:18.337521Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.337600Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T01:27:18.337606Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:18.337610Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:18.337612Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::London::0
2023-02-06T01:27:18.337614Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T01:27:18.337616Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.337679Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T01:27:18.337684Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:18.337688Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:18.337689Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTest2"::Merge::0
2023-02-06T01:27:18.337691Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTest2.json"
2023-02-06T01:27:18.337693Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.337755Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTest2"
2023-02-06T01:27:18.337760Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-02-06T01:27:18.338375Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-02-06T01:27:18.338403Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T01:27:18.362607Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:18.362704Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.362707Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:18.362750Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.362752Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:18.362808Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.362810Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 3
2023-02-06T01:27:18.362878Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.362881Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 4
2023-02-06T01:27:18.362951Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.363058Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:18.363062Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T01:27:18.363066Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.363069Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.711335Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.711356Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.711366Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:18.711369Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T01:27:18.711371Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.711373Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.711513Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.711520Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.711525Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:18.711528Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-02-06T01:27:18.711530Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.711532Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.711682Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.711688Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.711694Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:18.711696Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T01:27:18.711698Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.711700Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.711838Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.711844Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.711850Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:18.711852Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T01:27:18.711855Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.711857Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.711984Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.711990Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.711995Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:18.711997Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-02-06T01:27:18.712000Z  INFO evm_eth_compliance::statetest::executor: Path : "doubleSelfdestructTouch.json"
2023-02-06T01:27:18.712002Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:18.712125Z  INFO evm_eth_compliance::statetest::executor: UC : "doubleSelfdestructTouch"
2023-02-06T01:27:18.712131Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-02-06T01:27:18.713055Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-02-06T01:27:18.713088Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T01:27:18.737812Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:18.737911Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.737915Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:18.737968Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.737970Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 2
2023-02-06T01:27:18.738026Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:18.738096Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:18.738099Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Istanbul::0
2023-02-06T01:27:18.738103Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T01:27:18.738105Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T01:27:19.098664Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T01:27:19.098683Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3615148,
    events_root: None,
}
2023-02-06T01:27:19.098693Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:19.098696Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Berlin::0
2023-02-06T01:27:19.098698Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T01:27:19.098700Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T01:27:19.098788Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T01:27:19.098794Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T01:27:19.098799Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:19.098802Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::London::0
2023-02-06T01:27:19.098804Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T01:27:19.098806Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T01:27:19.098882Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T01:27:19.098888Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T01:27:19.098894Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:19.098896Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "extcodecopy"::Merge::0
2023-02-06T01:27:19.098899Z  INFO evm_eth_compliance::statetest::executor: Path : "extcodecopy.json"
2023-02-06T01:27:19.098901Z  INFO evm_eth_compliance::statetest::executor: TX len : 143
2023-02-06T01:27:19.098972Z  INFO evm_eth_compliance::statetest::executor: UC : "extcodecopy"
2023-02-06T01:27:19.098977Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-02-06T01:27:19.099657Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-02-06T01:27:19.099678Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T01:27:19.123506Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:19.123602Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.123605Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:19.123656Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.123726Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:19.123729Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Istanbul::0
2023-02-06T01:27:19.123731Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T01:27:19.123733Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.463173Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T01:27:19.463195Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.463200Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.463214Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:19.463219Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Berlin::0
2023-02-06T01:27:19.463221Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T01:27:19.463224Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.463309Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T01:27:19.463315Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.463319Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.463329Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:19.463332Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::London::0
2023-02-06T01:27:19.463334Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T01:27:19.463336Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.463407Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T01:27:19.463412Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.463415Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.463425Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:19.463428Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return0"::Merge::0
2023-02-06T01:27:19.463430Z  INFO evm_eth_compliance::statetest::executor: Path : "return0.json"
2023-02-06T01:27:19.463432Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.463502Z  INFO evm_eth_compliance::statetest::executor: UC : "return0"
2023-02-06T01:27:19.463508Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.463511Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.464196Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-02-06T01:27:19.464218Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T01:27:19.488611Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:19.488717Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.488721Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:19.488778Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.488852Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:19.488856Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Istanbul::0
2023-02-06T01:27:19.488859Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T01:27:19.488862Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.839210Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T01:27:19.839228Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.839235Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.839247Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:19.839251Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Berlin::0
2023-02-06T01:27:19.839252Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T01:27:19.839254Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.839334Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T01:27:19.839339Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.839342Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.839350Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:19.839352Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::London::0
2023-02-06T01:27:19.839353Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T01:27:19.839357Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.839427Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T01:27:19.839432Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.839435Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.839442Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:19.839445Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return1"::Merge::0
2023-02-06T01:27:19.839447Z  INFO evm_eth_compliance::statetest::executor: Path : "return1.json"
2023-02-06T01:27:19.839448Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:19.839514Z  INFO evm_eth_compliance::statetest::executor: UC : "return1"
2023-02-06T01:27:19.839518Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:19.839521Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:19.840295Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-02-06T01:27:19.840318Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T01:27:19.904567Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:19.904672Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.904676Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:19.904730Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:19.904803Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:19.904806Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Istanbul::0
2023-02-06T01:27:19.904809Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T01:27:19.904810Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.262746Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T01:27:20.262765Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.262770Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.262782Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:20.262785Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Berlin::0
2023-02-06T01:27:20.262787Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T01:27:20.262788Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.262871Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T01:27:20.262877Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.262880Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.262887Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:20.262889Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::London::0
2023-02-06T01:27:20.262890Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T01:27:20.262892Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.262953Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T01:27:20.262957Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.262960Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.262967Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:20.262969Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "return2"::Merge::0
2023-02-06T01:27:20.262971Z  INFO evm_eth_compliance::statetest::executor: Path : "return2.json"
2023-02-06T01:27:20.262972Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.263030Z  INFO evm_eth_compliance::statetest::executor: UC : "return2"
2023-02-06T01:27:20.263035Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.263037Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.263673Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-02-06T01:27:20.263700Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T01:27:20.293180Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:20.293289Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:20.293293Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:20.293347Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:20.293416Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:20.293419Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Istanbul::0
2023-02-06T01:27:20.293422Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T01:27:20.293424Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.635227Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T01:27:20.635249Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.635255Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.635270Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:20.635273Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Berlin::0
2023-02-06T01:27:20.635276Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T01:27:20.635278Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.635367Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T01:27:20.635373Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.635377Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.635387Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:20.635389Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::London::0
2023-02-06T01:27:20.635392Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T01:27:20.635394Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.635465Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T01:27:20.635470Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.635474Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.635483Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:20.635486Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideAddress"::Merge::0
2023-02-06T01:27:20.635488Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideAddress.json"
2023-02-06T01:27:20.635491Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.635558Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideAddress"
2023-02-06T01:27:20.635564Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.635567Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.636151Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-02-06T01:27:20.636178Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T01:27:20.660718Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:20.660828Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:20.660832Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:20.660888Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:20.660968Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:20.660971Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Istanbul::0
2023-02-06T01:27:20.660974Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T01:27:20.660976Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.997107Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T01:27:20.997127Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.997133Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.997145Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:20.997148Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Berlin::0
2023-02-06T01:27:20.997149Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T01:27:20.997151Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.997234Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T01:27:20.997239Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.997243Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.997250Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:20.997253Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::London::0
2023-02-06T01:27:20.997255Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T01:27:20.997257Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.997334Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T01:27:20.997340Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.997342Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.997350Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:20.997352Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCaller"::Merge::0
2023-02-06T01:27:20.997354Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCaller.json"
2023-02-06T01:27:20.997355Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:20.997421Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCaller"
2023-02-06T01:27:20.997426Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:20.997428Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:20.998034Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-02-06T01:27:20.998053Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.022347Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:21.022451Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.022454Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:21.022511Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.022584Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:21.022586Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Istanbul::0
2023-02-06T01:27:21.022589Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.022591Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.358975Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T01:27:21.359000Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.359006Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.359019Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:21.359023Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Berlin::0
2023-02-06T01:27:21.359025Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.359027Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.359132Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T01:27:21.359138Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.359141Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.359149Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:21.359151Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::London::0
2023-02-06T01:27:21.359152Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.359154Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.359227Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T01:27:21.359233Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.359237Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.359274Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:21.359283Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigLeft"::Merge::0
2023-02-06T01:27:21.359286Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.359289Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.359376Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigLeft"
2023-02-06T01:27:21.359382Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.359386Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.360319Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-02-06T01:27:21.360349Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.385351Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:21.385454Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.385457Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:21.385511Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.385582Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:21.385585Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Istanbul::0
2023-02-06T01:27:21.385588Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.385591Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.762492Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T01:27:21.762513Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.762519Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.762531Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:21.762535Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Berlin::0
2023-02-06T01:27:21.762536Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.762539Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.762623Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T01:27:21.762629Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.762632Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.762640Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:21.762642Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::London::0
2023-02-06T01:27:21.762644Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.762646Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.762714Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T01:27:21.762719Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.762722Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.762729Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:21.762731Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideCallerAddresTooBigRight"::Merge::0
2023-02-06T01:27:21.762733Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.762734Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:21.762799Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideCallerAddresTooBigRight"
2023-02-06T01:27:21.762805Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:21.762807Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:21.763536Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-02-06T01:27:21.763558Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T01:27:21.789526Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:21.789627Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.789631Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:21.789685Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:21.789757Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:21.789760Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Istanbul::0
2023-02-06T01:27:21.789763Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T01:27:21.789764Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.168476Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T01:27:22.168500Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.168506Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.168519Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:22.168524Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Berlin::0
2023-02-06T01:27:22.168526Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T01:27:22.168528Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.168636Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T01:27:22.168643Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.168646Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.168654Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:22.168656Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::London::0
2023-02-06T01:27:22.168657Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T01:27:22.168659Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.168725Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T01:27:22.168729Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.168732Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.168739Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:22.168741Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideNotExistingAccount"::Merge::0
2023-02-06T01:27:22.168743Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideNotExistingAccount.json"
2023-02-06T01:27:22.168745Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.168808Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideNotExistingAccount"
2023-02-06T01:27:22.168813Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.168815Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.169552Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-02-06T01:27:22.169574Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T01:27:22.193911Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:22.194018Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:22.194022Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:22.194076Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:22.194149Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:22.194152Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Istanbul::0
2023-02-06T01:27:22.194155Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T01:27:22.194157Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.527233Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T01:27:22.527254Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.527259Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.527271Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:22.527275Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Berlin::0
2023-02-06T01:27:22.527277Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T01:27:22.527279Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.527369Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T01:27:22.527375Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.527379Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.527388Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:22.527390Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::London::0
2023-02-06T01:27:22.527393Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T01:27:22.527394Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.527462Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T01:27:22.527468Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.527471Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.527478Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:22.527480Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideOrigin"::Merge::0
2023-02-06T01:27:22.527481Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideOrigin.json"
2023-02-06T01:27:22.527483Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:22.527546Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideOrigin"
2023-02-06T01:27:22.527550Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:22.527553Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:22.528178Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-02-06T01:27:22.528208Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.580961Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:22.581069Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:22.581072Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:22.581128Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:22.581200Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:22.581203Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Istanbul::0
2023-02-06T01:27:22.581206Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.581208Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T01:27:22.935578Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T01:27:22.935598Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T01:27:22.935603Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T01:27:22.935620Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:22.935623Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Berlin::0
2023-02-06T01:27:22.935625Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.935628Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T01:27:22.935809Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T01:27:22.935816Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T01:27:22.935819Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T01:27:22.935833Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:22.935835Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::London::0
2023-02-06T01:27:22.935837Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.935838Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T01:27:22.936008Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T01:27:22.936014Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T01:27:22.936017Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T01:27:22.936030Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:22.936032Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherPostDeath"::Merge::0
2023-02-06T01:27:22.936033Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.936035Z  INFO evm_eth_compliance::statetest::executor: TX len : 4
2023-02-06T01:27:22.936207Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherPostDeath"
2023-02-06T01:27:22.936213Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 3000000,
    events_root: None,
}
2023-02-06T01:27:22.936216Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
            ],
            cause: None,
        },
    ),
)
2023-02-06T01:27:22.936853Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-02-06T01:27:22.936883Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T01:27:23.000470Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:23.000574Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:23.000577Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:23.000630Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:23.000701Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:23.000705Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Istanbul::0
2023-02-06T01:27:23.000708Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T01:27:23.000709Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.332857Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T01:27:23.332879Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:23.332884Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.332897Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:23.332901Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Berlin::0
2023-02-06T01:27:23.332904Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T01:27:23.332906Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.333011Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T01:27:23.333020Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:23.333023Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.333034Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:23.333037Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::London::0
2023-02-06T01:27:23.333039Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T01:27:23.333042Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.333125Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T01:27:23.333130Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:23.333132Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.333140Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:23.333142Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "suicideSendEtherToMe"::Merge::0
2023-02-06T01:27:23.333143Z  INFO evm_eth_compliance::statetest::executor: Path : "suicideSendEtherToMe.json"
2023-02-06T01:27:23.333145Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.333210Z  INFO evm_eth_compliance::statetest::executor: UC : "suicideSendEtherToMe"
2023-02-06T01:27:23.333215Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 1000000,
    events_root: None,
}
2023-02-06T01:27:23.333218Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.333836Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-02-06T01:27:23.333862Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T01:27:23.357896Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-06T01:27:23.357995Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:23.357998Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-06T01:27:23.358049Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-06T01:27:23.358119Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-06T01:27:23.358122Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Istanbul::0
2023-02-06T01:27:23.358125Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T01:27:23.358127Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.689490Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T01:27:23.689511Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:23.689516Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.689527Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-06T01:27:23.689531Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Berlin::0
2023-02-06T01:27:23.689532Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T01:27:23.689534Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.689560Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T01:27:23.689564Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:23.689567Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.689576Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-06T01:27:23.689579Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::London::0
2023-02-06T01:27:23.689582Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T01:27:23.689585Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.689594Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T01:27:23.689599Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:23.689602Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.689611Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-06T01:27:23.689614Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "testRandomTest"::Merge::0
2023-02-06T01:27:23.689617Z  INFO evm_eth_compliance::statetest::executor: Path : "testRandomTest.json"
2023-02-06T01:27:23.689620Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
2023-02-06T01:27:23.689628Z  INFO evm_eth_compliance::statetest::executor: UC : "testRandomTest"
2023-02-06T01:27:23.689632Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 300000,
    events_root: None,
}
2023-02-06T01:27:23.689635Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-06T01:27:23.690239Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-02-06T01:27:23.690584Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 67 Files in Time:23.929969087s
=== Start ===
=== OK Status ===
Count :: 17
{
    "ABAcalls1.json::ABAcalls1": [
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
    "CallRecursiveBombLog2.json::CallRecursiveBombLog2": [
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
    "CallRecursiveBombLog.json::CallRecursiveBombLog": [
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
    "doubleSelfdestructTouch.json::doubleSelfdestructTouch": [
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
    "extcodecopy.json::extcodecopy": [
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
    "CreateHashCollision.json::CreateHashCollision": [
        "Istanbul | 0 | ExitCode { value: 0 }",
    ],
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
    ],
    "callerAccountBalance.json::callerAccountBalance": [
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
    "CallRecursiveBomb0.json::CallRecursiveBomb0": [
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
    "ABAcallsSuicide0.json::ABAcallsSuicide0": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
Count :: 52
{
    "CallToReturn1ForDynamicJump0.json::CallToReturn1ForDynamicJump0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorOutOfMemoryBonds0.json::createNameRegistratorOutOfMemoryBonds0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideCaller.json::suicideCaller": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToReturn1ForDynamicJump1.json::CallToReturn1ForDynamicJump1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideSendEtherToMe.json::suicideSendEtherToMe": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CreateHashCollision.json::CreateHashCollision": [
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
    "CallToNameRegistratorAddressTooBigRight.json::CallToNameRegistratorAddressTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorZeorSizeMemExpansion.json::CallToNameRegistratorZeorSizeMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorTooMuchMemory0.json::CallToNameRegistratorTooMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorTooMuchMemory2.json::CallToNameRegistratorTooMuchMemory2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToReturn1.json::CallToReturn1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "PostToReturn1.json::PostToReturn1": [
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
    "createWithInvalidOpcode.json::createWithInvalidOpcode": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "return2.json::return2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorZeroMem2.json::createNameRegistratorZeroMem2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CalltoReturn2.json::CalltoReturn2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "ABAcalls0.json::ABAcalls0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorMemOOGAndInsufficientBalance.json::CallToNameRegistratorMemOOGAndInsufficientBalance": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "ABAcalls3.json::ABAcalls3": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistratorZeroMemExpanion.json::callcodeToNameRegistratorZeroMemExpanion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorZeroMem.json::createNameRegistratorZeroMem": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideAddress.json::suicideAddress": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideCallerAddresTooBigLeft.json::suicideCallerAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideCallerAddresTooBigRight.json::suicideCallerAddresTooBigRight": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideOrigin.json::suicideOrigin": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideNotExistingAccount.json::suicideNotExistingAccount": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorValueTooHigh.json::createNameRegistratorValueTooHigh": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallRecursiveBomb1.json::CallRecursiveBomb1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorNotMuchMemory0.json::CallToNameRegistratorNotMuchMemory0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistrator.json::createNameRegistrator": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistrator0.json::CallToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorOutOfMemoryBonds1.json::createNameRegistratorOutOfMemoryBonds1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToReturn1.json::callcodeToReturn1": [
        "Istanbul | 0 | ExitCode { value: 35 }",
        "Berlin | 0 | ExitCode { value: 35 }",
        "London | 0 | ExitCode { value: 35 }",
        "Merge | 0 | ExitCode { value: 35 }",
    ],
    "createNameRegistratorZeroMemExpansion.json::createNameRegistratorZeroMemExpansion": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "suicideSendEtherPostDeath.json::suicideSendEtherPostDeath": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "balanceInputAddressTooBig.json::balanceInputAddressTooBig": [
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
    "CallToNameRegistratorAddressTooBigLeft.json::CallToNameRegistratorAddressTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorOutOfGas.json::CallToNameRegistratorOutOfGas": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "return0.json::return0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "createNameRegistratorOOG_MemExpansionOOV.json::createNameRegistratorOOG_MemExpansionOOV": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallToNameRegistratorNotMuchMemory1.json::CallToNameRegistratorNotMuchMemory1": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistrator0.json::callcodeToNameRegistrator0": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallRecursiveBomb0_OOG_atMaxCallDepth.json::CallRecursiveBomb0_OOG_atMaxCallDepth": [
        "Merge | 0 | ExitCode { value: 38 }",
    ],
    "return1.json::return1": [
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
    "TestNameRegistrator.json::TestNameRegistrator": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistratorAddresTooBigLeft.json::callcodeToNameRegistratorAddresTooBigLeft": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "CallRecursiveBomb2.json::CallRecursiveBomb2": [
        "Istanbul | 0 | ExitCode { value: 7 }",
        "Berlin | 0 | ExitCode { value: 7 }",
        "London | 0 | ExitCode { value: 7 }",
        "Merge | 0 | ExitCode { value: 7 }",
    ],
    "callcodeToNameRegistratorAddresTooBigRight.json::callcodeToNameRegistratorAddresTooBigRight": [
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