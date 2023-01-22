> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |

KO :: USR_ASSERTION_FAILED

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreateTest/CREATE_HighNonce.json#L16

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Hit with error `pub const USR_ASSERTION_FAILED: ExitCode = ExitCode::new(24);`

```
2023-01-22T14:04:02.544603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.544612Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.544619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.545236Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.545255Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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

> Opcode

@0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b

```
0000 PUSH32 0x60016000f3000000000000000000000000000000000000000000000000000000
0021 PUSH1 0x00
0023 MSTORE
0024 PUSH1 0x05
0026 PUSH1 0x00
0028 PUSH1 0x00
002a CREATE
002b PUSH1 0x00
002d SSTORE
002e PUSH1 0x01
0030 PUSH1 0x01
0032 SSTORE
```

> Execution Trace

```
2023-01-22T14:03:50.341284Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json", Total Files :: 1
2023-01-22T14:03:50.341727Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:03:50.458043Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.539660Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T14:04:02.539848Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:04:02.539926Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.543205Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T14:04:02.543360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:04:02.544548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-22T14:04:02.544593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Frontier::0
2023-01-22T14:04:02.544603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.544612Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.544619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.545236Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.545255Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.545288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-22T14:04:02.545310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Homestead::0
2023-01-22T14:04:02.545317Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.545325Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.545331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.545902Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.545917Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.545946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-22T14:04:02.545968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::EIP150::0
2023-01-22T14:04:02.545975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.545982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.545988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.546567Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.546582Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.546610Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-22T14:04:02.546634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::EIP158::0
2023-01-22T14:04:02.546641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.546648Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.546654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.547229Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.547244Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.547271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-22T14:04:02.547295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Byzantium::0
2023-01-22T14:04:02.547302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.547309Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.547315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.547891Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.547907Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.547934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-22T14:04:02.547958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Constantinople::0
2023-01-22T14:04:02.547965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.547972Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.547978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.548545Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.548560Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.548588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T14:04:02.548611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::ConstantinopleFix::0
2023-01-22T14:04:02.548618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.548625Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.548632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.549215Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.549230Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.549258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T14:04:02.549281Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Istanbul::0
2023-01-22T14:04:02.549288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.549296Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.549303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.549877Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.549892Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.549921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T14:04:02.549943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Berlin::0
2023-01-22T14:04:02.549950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.549957Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.549963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.550538Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.550552Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.550580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T14:04:02.550604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::London::0
2023-01-22T14:04:02.550611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.550618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.550624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.551190Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.551207Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.551233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T14:04:02.551258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonce"::Merge::0
2023-01-22T14:04:02.551264Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.551271Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:04:02.551277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:04:02.551855Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1594165,
    events_root: None,
}
2023-01-22T14:04:02.551871Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:04:02.553886Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonce.json"
2023-01-22T14:04:02.554137Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.093881808s
```