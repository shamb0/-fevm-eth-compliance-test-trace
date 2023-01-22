> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |

KO :: USR_ASSERTION_FAILED

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Hit with error `pub const USR_ASSERTION_FAILED: ExitCode = ExitCode::new(24);

```
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.865613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3828898,
    events_root: None,
}
2023-01-22T13:51:11.865652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T13:51:11.865676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::ConstantinopleFix::0
2023-01-22T13:51:11.865683Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.865690Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.865695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.866284Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
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
2023-01-22T13:50:59.951510Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json", Total Files :: 1
2023-01-22T13:50:59.951953Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:00.064381Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.859470Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T13:51:11.859657Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:51:11.859736Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.862934Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T13:51:11.863089Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T13:51:11.864292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-22T13:51:11.864335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::Constantinople::0
2023-01-22T13:51:11.864345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.864356Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.864363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.865613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3828898,
    events_root: None,
}
2023-01-22T13:51:11.865652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-22T13:51:11.865676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::ConstantinopleFix::0
2023-01-22T13:51:11.865683Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.865690Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.865695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.866284Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
2023-01-22T13:51:11.866300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T13:51:11.866331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T13:51:11.866354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::Istanbul::0
2023-01-22T13:51:11.866361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.866368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.866374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.866949Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
2023-01-22T13:51:11.866964Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T13:51:11.866992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T13:51:11.867015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::Berlin::0
2023-01-22T13:51:11.867022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.867029Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.867035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.867625Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
2023-01-22T13:51:11.867640Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T13:51:11.867668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T13:51:11.867691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::London::0
2023-01-22T13:51:11.867698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.867705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.867711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.868288Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
2023-01-22T13:51:11.868304Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T13:51:11.868331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T13:51:11.868354Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_HighNonceMinus1"::Merge::0
2023-01-22T13:51:11.868361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.868368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T13:51:11.868374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T13:51:11.868951Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 24,
    },
    return_data: RawBytes {  },
    gas_used: 1611823,
    events_root: None,
}
2023-01-22T13:51:11.868966Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
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
2023-01-22T13:51:11.871183Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreate2/CREATE2_HighNonceMinus1.json"
2023-01-22T13:51:11.871535Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.804639474s
```