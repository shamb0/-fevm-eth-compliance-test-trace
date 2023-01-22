> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |

KO :: USR_ASSERTION_FAILED

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Hit with error `pub const USR_ASSERTION_FAILED: ExitCode = ExitCode::new(24);

```
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.053584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13320387,
    events_root: None,
}
2023-01-22T14:16:56.053645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-22T14:16:56.053670Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Homestead::0
2023-01-22T14:16:56.053677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.053684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.053690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.054299Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
```

> Execution Trace


```
2023-01-22T14:16:44.159003Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json", Total Files :: 1
2023-01-22T14:16:44.159429Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:44.273844Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.044803Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T14:16:56.044996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:16:56.045078Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.048386Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T14:16:56.048547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:16:56.049724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-22T14:16:56.049770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Frontier::0
2023-01-22T14:16:56.049783Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.049791Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.049798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [208, 97, 176, 138, 132, 235, 199, 15, 231, 151, 249, 189, 98, 244, 38, 158, 248, 39, 74, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.053584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13320387,
    events_root: None,
}
2023-01-22T14:16:56.053645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-22T14:16:56.053670Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Homestead::0
2023-01-22T14:16:56.053677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.053684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.053690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.054299Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.054315Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.054348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-22T14:16:56.054372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::EIP150::0
2023-01-22T14:16:56.054378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.054386Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.054393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.054976Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.054991Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.055021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-22T14:16:56.055044Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::EIP158::0
2023-01-22T14:16:56.055051Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.055059Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.055066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.055658Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.055675Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.055703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-22T14:16:56.055726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Byzantium::0
2023-01-22T14:16:56.055733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.055741Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.055747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.056329Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.056346Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.056374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-22T14:16:56.056398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Constantinople::0
2023-01-22T14:16:56.056405Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.056412Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.056418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.057001Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.057017Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.057045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T14:16:56.057067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::ConstantinopleFix::0
2023-01-22T14:16:56.057075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.057083Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.057089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.057672Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.057689Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.057716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T14:16:56.057740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Istanbul::0
2023-01-22T14:16:56.057747Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.057754Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.057760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.058341Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.058358Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.058386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T14:16:56.058408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Berlin::0
2023-01-22T14:16:56.058415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.058423Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.058429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.059008Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.059023Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.059051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T14:16:56.059074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::London::0
2023-01-22T14:16:56.059080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.059088Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.059095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.059681Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.059697Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.059725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T14:16:56.059748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_HighNonceMinus1"::Merge::0
2023-01-22T14:16:56.059756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.059763Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T14:16:56.059769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:16:56.060350Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1612691,
    events_root: None,
}
2023-01-22T14:16:56.060365Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T14:16:56.062724Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreateTest/CREATE_HighNonceMinus1.json"
2023-01-22T14:16:56.063072Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.786575943s
```