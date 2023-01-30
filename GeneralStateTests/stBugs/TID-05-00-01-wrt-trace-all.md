> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBugs

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBugs \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases passed.

> Execution Trace

* Following use-cases are failed

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-05-01 | evmBytecode |


- Hit with error `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS` (ExitCode::38)

| Test ID | Use-Case |
| --- | --- |
| | returndatacopyPythonBug_Tue_03_48_41-1432 |

> Execution Trace

```
2023-01-27T02:01:07.662322Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json", Total Files :: 1
2023-01-27T02:01:07.903188Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T02:01:07.903332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:07.903336Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T02:01:07.903389Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:07.903465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:07.903468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Istanbul::0
2023-01-27T02:01:07.903471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-27T02:01:07.903474Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:07.903476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:08.345983Z  INFO evm_eth_compliance::statetest::runner: UC : "evmBytecode"
2023-01-27T02:01:08.345998Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1540208,
    events_root: None,
}
2023-01-27T02:01:08.346005Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-27T02:01:08.346018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:08.346023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Berlin::0
2023-01-27T02:01:08.346024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-27T02:01:08.346027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:08.346029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:08.346134Z  INFO evm_eth_compliance::statetest::runner: UC : "evmBytecode"
2023-01-27T02:01:08.346138Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1540208,
    events_root: None,
}
2023-01-27T02:01:08.346141Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-27T02:01:08.346151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:08.346153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::London::0
2023-01-27T02:01:08.346155Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-27T02:01:08.346157Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:08.346158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:08.346248Z  INFO evm_eth_compliance::statetest::runner: UC : "evmBytecode"
2023-01-27T02:01:08.346253Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1540208,
    events_root: None,
}
2023-01-27T02:01:08.346257Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-27T02:01:08.346267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:08.346269Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "evmBytecode"::Merge::0
2023-01-27T02:01:08.346271Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/evmBytecode.json"
2023-01-27T02:01:08.346274Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:08.346276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:08.346366Z  INFO evm_eth_compliance::statetest::runner: UC : "evmBytecode"
2023-01-27T02:01:08.346370Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1540208,
    events_root: None,
}
2023-01-27T02:01:08.346373Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 401,
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
2023-01-27T02:01:08.348057Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:443.198218ms
2023-01-27T02:01:08.637734Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json", Total Files :: 1
2023-01-27T02:01:08.673448Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T02:01:08.673583Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:08.673586Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T02:01:08.673639Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:08.673641Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T02:01:08.673703Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:08.673778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:08.673781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"::Istanbul::0
2023-01-27T02:01:08.673784Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json"
2023-01-27T02:01:08.673788Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:08.673789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.040279Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"
2023-01-27T02:01:09.040303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5916535,
    events_root: None,
}
2023-01-27T02:01:09.040323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:09.040329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"::Berlin::0
2023-01-27T02:01:09.040332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json"
2023-01-27T02:01:09.040335Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.040337Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.040549Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"
2023-01-27T02:01:09.040554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.040562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:09.040565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"::London::0
2023-01-27T02:01:09.040567Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json"
2023-01-27T02:01:09.040569Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.040571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.040743Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"
2023-01-27T02:01:09.040748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.040757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:09.040759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"::Merge::0
2023-01-27T02:01:09.040761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json"
2023-01-27T02:01:09.040764Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.040765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.040945Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192"
2023-01-27T02:01:09.040951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.043639Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.517183ms
2023-01-27T02:01:09.329604Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json", Total Files :: 1
2023-01-27T02:01:09.360387Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T02:01:09.360519Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:09.360523Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T02:01:09.360583Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:09.360586Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T02:01:09.360646Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:09.360722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:09.360725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Istanbul::0
2023-01-27T02:01:09.360728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-27T02:01:09.360731Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.360732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.756250Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"
2023-01-27T02:01:09.756275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5916535,
    events_root: None,
}
2023-01-27T02:01:09.756300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:09.756308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Berlin::0
2023-01-27T02:01:09.756312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-27T02:01:09.756316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.756318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.756575Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"
2023-01-27T02:01:09.756582Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.756589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:09.756592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::London::0
2023-01-27T02:01:09.756594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-27T02:01:09.756611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.756619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.756955Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"
2023-01-27T02:01:09.756971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.756986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:09.756993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Merge::0
2023-01-27T02:01:09.756998Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-27T02:01:09.757002Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T02:01:09.757004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:09.757224Z  INFO evm_eth_compliance::statetest::runner: UC : "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"
2023-01-27T02:01:09.757243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2646118,
    events_root: None,
}
2023-01-27T02:01:09.760210Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:396.876518ms
2023-01-27T02:01:10.055333Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json", Total Files :: 1
2023-01-27T02:01:10.140366Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T02:01:10.140512Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:10.140516Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T02:01:10.140582Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:10.140585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T02:01:10.140651Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:10.140653Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T02:01:10.140717Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:10.140719Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T02:01:10.140775Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:10.140853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:10.140857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-27T02:01:10.140860Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.140864Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.140865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-27T02:01:10.754533Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.754552Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 16968288,
    events_root: None,
}
2023-01-27T02:01:10.754560Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.754621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:10.754627Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-27T02:01:10.754630Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.754635Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.754638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-27T02:01:10.756095Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.756119Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17199371,
    events_root: None,
}
2023-01-27T02:01:10.756127Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.756203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:10.756211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-27T02:01:10.756214Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.756219Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.756221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-27T02:01:10.757811Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.757828Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17017298,
    events_root: None,
}
2023-01-27T02:01:10.757835Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.757892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:10.757897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Istanbul::0
2023-01-27T02:01:10.757900Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.757903Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.757905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-27T02:01:10.758962Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.758971Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17192334,
    events_root: None,
}
2023-01-27T02:01:10.758975Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.759008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:10.759011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-27T02:01:10.759014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.759017Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.759019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-27T02:01:10.759811Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.759816Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 16815389,
    events_root: None,
}
2023-01-27T02:01:10.759819Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.759852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:10.759854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-27T02:01:10.759857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.759859Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.759861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-27T02:01:10.760658Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.760663Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17064406,
    events_root: None,
}
2023-01-27T02:01:10.760667Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.760706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:10.760709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-27T02:01:10.760712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.760716Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.760718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-27T02:01:10.761520Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.761526Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17064705,
    events_root: None,
}
2023-01-27T02:01:10.761530Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.761568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:10.761571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Berlin::0
2023-01-27T02:01:10.761574Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.761578Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.761580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-27T02:01:10.762384Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.762391Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17071574,
    events_root: None,
}
2023-01-27T02:01:10.762395Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.762433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:10.762436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-27T02:01:10.762439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.762443Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.762444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
2023-01-27T02:01:10.763221Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.763227Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17056495,
    events_root: None,
}
2023-01-27T02:01:10.763231Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.763271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:10.763274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-27T02:01:10.763277Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.763280Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.763282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
2023-01-27T02:01:10.764143Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.764150Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 16934846,
    events_root: None,
}
2023-01-27T02:01:10.764154Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.764193Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:10.764197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-27T02:01:10.764200Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.764203Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.764205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
2023-01-27T02:01:10.765290Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.765299Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17109657,
    events_root: None,
}
2023-01-27T02:01:10.765303Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.765345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:10.765350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::London::0
2023-01-27T02:01:10.765352Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.765356Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.765357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
2023-01-27T02:01:10.766520Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.766530Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17420422,
    events_root: None,
}
2023-01-27T02:01:10.766535Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.766582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:10.766586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-27T02:01:10.766590Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.766594Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.766596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
2023-01-27T02:01:10.767572Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.767580Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 15898537,
    events_root: None,
}
2023-01-27T02:01:10.767585Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.767623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:10.767627Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-27T02:01:10.767629Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.767632Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.767634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
2023-01-27T02:01:10.768708Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.768714Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 17006026,
    events_root: None,
}
2023-01-27T02:01:10.768717Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.768754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:10.768757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-27T02:01:10.768759Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.768763Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.768764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
2023-01-27T02:01:10.769545Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.769550Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 16942000,
    events_root: None,
}
2023-01-27T02:01:10.769553Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.769584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:10.769587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returndatacopyPythonBug_Tue_03_48_41-1432"::Merge::0
2023-01-27T02:01:10.769589Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/returndatacopyPythonBug_Tue_03_48_41-1432.json"
2023-01-27T02:01:10.769593Z  INFO evm_eth_compliance::statetest::runner: TX len : 676
2023-01-27T02:01:10.769594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 192, 211, 114, 55, 161, 246, 189, 98, 2, 174, 212, 181, 167, 41, 13, 252, 218, 101, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
2023-01-27T02:01:10.770358Z  INFO evm_eth_compliance::statetest::runner: UC : "returndatacopyPythonBug_Tue_03_48_41-1432"
2023-01-27T02:01:10.770364Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 16992123,
    events_root: None,
}
2023-01-27T02:01:10.770367Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 402,
                    method: 3844450837,
                    code: ExitCode {
                        value: 33,
                    },
                    message: "contract reverted",
                },
                Frame {
                    source: 403,
                    method: 3844450837,
                    code: ExitCode {
                        value: 25,
                    },
                    message: "ABORT(pc=42): cannot transfer value when read-only",
                },
                Frame {
                    source: 404,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=303): returndatacopy start 503 exceeds return-data length 0",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T02:01:10.772467Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:630.037701ms
2023-01-27T02:01:11.059152Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json", Total Files :: 1
2023-01-27T02:01:11.319863Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T02:01:11.320011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:11.320016Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T02:01:11.320068Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:11.320070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T02:01:11.320129Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:11.320131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T02:01:11.320186Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T02:01:11.320260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T02:01:11.320263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Istanbul::0
2023-01-27T02:01:11.320266Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.320269Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.320270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.693521Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.693537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.693549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T02:01:11.693553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Istanbul::1
2023-01-27T02:01:11.693555Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.693558Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.693559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.693682Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.693687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.693693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T02:01:11.693696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Berlin::0
2023-01-27T02:01:11.693698Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.693700Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.693702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.693814Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.693818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.693823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T02:01:11.693825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Berlin::1
2023-01-27T02:01:11.693827Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.693829Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.693831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.693963Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.693967Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.693974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T02:01:11.693976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::London::0
2023-01-27T02:01:11.693978Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.693980Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.693982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.694093Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.694098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.694103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T02:01:11.694105Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::London::1
2023-01-27T02:01:11.694106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.694109Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.694110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.694221Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.694225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.694230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T02:01:11.694232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Merge::0
2023-01-27T02:01:11.694234Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.694236Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.694238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.694349Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.694353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.694359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T02:01:11.694362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Merge::1
2023-01-27T02:01:11.694364Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-27T02:01:11.694366Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T02:01:11.694368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T02:01:11.694477Z  INFO evm_eth_compliance::statetest::runner: UC : "staticcall_createfails"
2023-01-27T02:01:11.694482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1778233,
    events_root: None,
}
2023-01-27T02:01:11.696168Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.630016ms
```
