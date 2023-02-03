> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stAttackTest/ContractCreationSpam.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Hit with error `SYS_OUT_OF_GAS`(ExitCode::7) as expected

```
Finished Processing of 1 Files in Time:721.748566ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "ContractCreationSpam.json::ContractCreationSpam": [
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

> Execution Trace

```
2023-02-03T09:01:01.110123Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json", Total Files :: 1
2023-02-03T09:01:01.110449Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-02-03T09:01:01.138796Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-03T09:01:01.138935Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-03T09:01:01.138940Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-03T09:01:01.138995Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-03T09:01:01.139065Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-03T09:01:01.139068Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ContractCreationSpam"::Istanbul::0
2023-02-03T09:01:01.139071Z  INFO evm_eth_compliance::statetest::executor: Path : "ContractCreationSpam.json"
2023-02-03T09:01:01.139073Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-02-03T09:01:01.858871Z  INFO evm_eth_compliance::statetest::executor: UC : "ContractCreationSpam"
2023-02-03T09:01:01.858890Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-03T09:01:01.858897Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-03T09:01:01.858927Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-03T09:01:01.858931Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ContractCreationSpam"::Berlin::0
2023-02-03T09:01:01.858933Z  INFO evm_eth_compliance::statetest::executor: Path : "ContractCreationSpam.json"
2023-02-03T09:01:01.858936Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-02-03T09:01:01.859531Z  INFO evm_eth_compliance::statetest::executor: UC : "ContractCreationSpam"
2023-02-03T09:01:01.859539Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-03T09:01:01.859542Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-03T09:01:01.859560Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-03T09:01:01.859563Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ContractCreationSpam"::London::0
2023-02-03T09:01:01.859565Z  INFO evm_eth_compliance::statetest::executor: Path : "ContractCreationSpam.json"
2023-02-03T09:01:01.859567Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-02-03T09:01:01.859998Z  INFO evm_eth_compliance::statetest::executor: UC : "ContractCreationSpam"
2023-02-03T09:01:01.860005Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-03T09:01:01.860010Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-03T09:01:01.860028Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-03T09:01:01.860030Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "ContractCreationSpam"::Merge::0
2023-02-03T09:01:01.860032Z  INFO evm_eth_compliance::statetest::executor: Path : "ContractCreationSpam.json"
2023-02-03T09:01:01.860034Z  INFO evm_eth_compliance::statetest::executor: TX len : 0
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-02-03T09:01:01.860510Z  INFO evm_eth_compliance::statetest::executor: UC : "ContractCreationSpam"
2023-02-03T09:01:01.860517Z  WARN evm_eth_compliance::statetest::executor: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 7,
    },
    return_data: RawBytes {  },
    gas_used: 10000000,
    events_root: None,
}
2023-02-03T09:01:01.860520Z  WARN evm_eth_compliance::statetest::executor: failure_info => Some(
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
2023-02-03T09:01:01.862331Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-02-03T09:01:01.862528Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:721.748566ms
=== Start ===
=== OK Status ===
None
=== KO Status ===
Count :: 1
{
    "ContractCreationSpam.json::ContractCreationSpam": [
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
