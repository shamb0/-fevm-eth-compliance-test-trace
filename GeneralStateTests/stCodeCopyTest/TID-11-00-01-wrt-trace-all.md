> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCodeCopyTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCodeCopyTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, all use-cases passed.

> Execution Trace

```
2023-01-26T15:53:49.478188Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTargetRangeLongerThanCodeTests.json", Total Files :: 1
2023-01-26T15:53:49.531524Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:53:49.531682Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:49.531686Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:53:49.531736Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:49.531738Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T15:53:49.531796Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:49.531868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:53:49.531870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTargetRangeLongerThanCodeTests"::Istanbul::0
2023-01-26T15:53:49.531873Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTargetRangeLongerThanCodeTests.json"
2023-01-26T15:53:49.531877Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:49.531878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:49.887701Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTargetRangeLongerThanCodeTests"
2023-01-26T15:53:49.887718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4896585,
    events_root: None,
}
2023-01-26T15:53:49.887730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:53:49.887734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTargetRangeLongerThanCodeTests"::Berlin::0
2023-01-26T15:53:49.887737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTargetRangeLongerThanCodeTests.json"
2023-01-26T15:53:49.887742Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:49.887743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:49.887996Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTargetRangeLongerThanCodeTests"
2023-01-26T15:53:49.888001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954631,
    events_root: None,
}
2023-01-26T15:53:49.888008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:53:49.888010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTargetRangeLongerThanCodeTests"::London::0
2023-01-26T15:53:49.888013Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTargetRangeLongerThanCodeTests.json"
2023-01-26T15:53:49.888015Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:49.888017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:49.888296Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTargetRangeLongerThanCodeTests"
2023-01-26T15:53:49.888301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954631,
    events_root: None,
}
2023-01-26T15:53:49.888308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:53:49.888311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTargetRangeLongerThanCodeTests"::Merge::0
2023-01-26T15:53:49.888313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTargetRangeLongerThanCodeTests.json"
2023-01-26T15:53:49.888316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:49.888317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:49.888557Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTargetRangeLongerThanCodeTests"
2023-01-26T15:53:49.888562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3954631,
    events_root: None,
}
2023-01-26T15:53:49.890195Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.051037ms
2023-01-26T15:53:50.154154Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTests.json", Total Files :: 1
2023-01-26T15:53:50.369568Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:53:50.369733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:50.369737Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:53:50.369787Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:50.369789Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T15:53:50.369846Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:50.369848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T15:53:50.369899Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:50.369902Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T15:53:50.369953Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:53:50.370023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:53:50.370026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTests"::Istanbul::0
2023-01-26T15:53:50.370029Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTests.json"
2023-01-26T15:53:50.370032Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:50.370034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:50.733125Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTests"
2023-01-26T15:53:50.733140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8929323,
    events_root: None,
}
2023-01-26T15:53:50.733160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:53:50.733165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTests"::Berlin::0
2023-01-26T15:53:50.733168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTests.json"
2023-01-26T15:53:50.733171Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:50.733172Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:50.733620Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTests"
2023-01-26T15:53:50.733625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6953466,
    events_root: None,
}
2023-01-26T15:53:50.733635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:53:50.733638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTests"::London::0
2023-01-26T15:53:50.733639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTests.json"
2023-01-26T15:53:50.733642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:50.733643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:50.734074Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTests"
2023-01-26T15:53:50.734080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6953466,
    events_root: None,
}
2023-01-26T15:53:50.734089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:53:50.734092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ExtCodeCopyTests"::Merge::0
2023-01-26T15:53:50.734094Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCodeCopyTest/ExtCodeCopyTests.json"
2023-01-26T15:53:50.734097Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:53:50.734098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:53:50.734530Z  INFO evm_eth_compliance::statetest::runner: UC : "ExtCodeCopyTests"
2023-01-26T15:53:50.734535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6953466,
    events_root: None,
}
2023-01-26T15:53:50.736081Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.98073ms
```