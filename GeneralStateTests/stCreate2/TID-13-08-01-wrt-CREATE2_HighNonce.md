> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |

KO :: USR_ASSERTION_FAILED

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreate2/CREATE2_HighNonce.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Hit with error `pub const USR_ASSERTION_FAILED: ExitCode = ExitCode::new(24);`

```
2023-01-22T13:32:11.114701Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.114722Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
```

> Opcodes

@0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b

```
0000 PUSH32 0x60016000f3000000000000000000000000000000000000000000000000000000
0021 PUSH1 0x00
0023 MSTORE
0024 PUSH1 0x00
0026 PUSH1 0x05
0028 PUSH1 0x00
002a PUSH1 0x00
002c CREATE2
002d PUSH1 0x00
002f SSTORE
0030 PUSH1 0x01
0032 PUSH1 0x01
0034 SSTORE
```

> Execution Trace

```
2023-01-22T13:31:58.585156Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json", Total Files :: 1
2023-01-22T13:31:58.585555Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:31:58.697753Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.109282Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T13:32:11.109466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:32:11.109545Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.112696Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T13:32:11.112851Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:32:11.114018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-22T13:32:11.114067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::Constantinople::0
2023-01-22T13:32:11.114076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.114084Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.114091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.114701Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.114722Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.114754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T13:32:11.114778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::ConstantinopleFix::0
2023-01-22T13:32:11.114785Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.114792Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.114798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.115362Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.115377Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.115405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T13:32:11.115428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::Istanbul::0
2023-01-22T13:32:11.115435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.115443Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.115448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.116017Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.116032Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.116061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T13:32:11.116084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::Berlin::0
2023-01-22T13:32:11.116091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.116098Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.116104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.116665Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.116680Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.116707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T13:32:11.116731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::London::0
2023-01-22T13:32:11.116738Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.116745Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.116751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.117312Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.117327Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.117355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T13:32:11.117378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonce"::Merge::0
2023-01-22T13:32:11.117385Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.117393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:32:11.117399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:32:11.117964Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1593728,
    events_root: None,
}
2023-01-22T13:32:11.117979Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 201,
                    method: 3844450837,
                    code: ExitCode {
                        value: 24,
                    },
                    message: "panicked at 'called `Option::unwrap()` on a `None` value', actors/evm/src/interpreter/system.rs:210:22",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-22T13:32:11.120516Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonce.json"
2023-01-22T13:32:11.120812Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.420282662s
```