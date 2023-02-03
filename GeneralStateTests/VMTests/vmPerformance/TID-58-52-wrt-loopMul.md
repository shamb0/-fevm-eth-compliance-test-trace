> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmPerformance/loopMul.json#L168

> For Review

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, takes too long to complete. Better to have review on
gas consumed for each use-cases.

```
INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:506.150602693s
=== Start ===
=== OK Status ===
Count :: 1
{
    "loopMul.json::loopMul": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 1 | ExitCode { value: 0 }",
        "Istanbul | 2 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 1 | ExitCode { value: 0 }",
        "Berlin | 2 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 1 | ExitCode { value: 0 }",
        "London | 2 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 1 | ExitCode { value: 0 }",
        "Merge | 2 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
```

> Execution Trace

```
 Compiling evm_eth_compliance v10.0.0-alpha.1 (/home/popoyi/dscbox/sun/ws-020-blocks/ws-030-filecoin-project/dev-030-01-fvm/fevm-eth-compliance-test)
    Finished release [optimized] target(s) in 26.00s
     Running `target/release/evm_eth_compliance statetest`
2023-02-03T09:19:59.348071Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json", Total Files :: 1
2023-02-03T09:19:59.348334Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
2023-02-03T09:19:59.377463Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 0
2023-02-03T09:19:59.377608Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-03T09:19:59.377613Z  INFO evm_eth_compliance::statetest::executor: Pre-Block Iteration :: 1
2023-02-03T09:19:59.377671Z  INFO evm_eth_compliance::statetest::executor: New State ID Updated
2023-02-03T09:19:59.377742Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 0
2023-02-03T09:19:59.377746Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Istanbul::0
2023-02-03T09:19:59.377750Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:19:59.377753Z  INFO evm_eth_compliance::statetest::executor: TX len : 100
2023-02-03T09:20:31.030171Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:20:31.030192Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820e2ef8b895ee03259ee57850b1a1ed4aa7689bec352659200e63440303f9d0b81 },
    gas_used: 419377635088,
    events_root: None,
}
2023-02-03T09:20:31.030208Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 1
2023-02-03T09:20:31.030213Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Istanbul::1
2023-02-03T09:20:31.030216Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:20:31.030219Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:21:50.683343Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:21:50.683364Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffaaffffffffffffffffbbffffffffffffff0009 },
    gas_used: 1100562893549,
    events_root: None,
}
2023-02-03T09:21:50.683380Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Istanbul 2
2023-02-03T09:21:50.683385Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Istanbul::2
2023-02-03T09:21:50.683388Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:21:50.683390Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:22:04.968463Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:22:04.968487Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200e1c6aac6663c379a52d9ccc7ba4757131020772d41447dfcf478cf9fb0c2bbf },
    gas_used: 262579344797,
    events_root: None,
}
2023-02-03T09:22:04.968505Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 0
2023-02-03T09:22:04.968511Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Berlin::0
2023-02-03T09:22:04.968514Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:22:04.968517Z  INFO evm_eth_compliance::statetest::executor: TX len : 100
2023-02-03T09:22:36.615419Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:22:36.615443Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820e2ef8b895ee03259ee57850b1a1ed4aa7689bec352659200e63440303f9d0b81 },
    gas_used: 419377651718,
    events_root: None,
}
2023-02-03T09:22:36.615463Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 1
2023-02-03T09:22:36.615468Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Berlin::1
2023-02-03T09:22:36.615470Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:22:36.615472Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:23:57.248468Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:23:57.248500Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffaaffffffffffffffffbbffffffffffffff0009 },
    gas_used: 1100562893549,
    events_root: None,
}
2023-02-03T09:23:57.248525Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Berlin 2
2023-02-03T09:23:57.248533Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Berlin::2
2023-02-03T09:23:57.248538Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:23:57.248542Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:24:11.847799Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:24:11.847824Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200e1c6aac6663c379a52d9ccc7ba4757131020772d41447dfcf478cf9fb0c2bbf },
    gas_used: 262579344797,
    events_root: None,
}
2023-02-03T09:24:11.847840Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 0
2023-02-03T09:24:11.847846Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::London::0
2023-02-03T09:24:11.847849Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:24:11.847853Z  INFO evm_eth_compliance::statetest::executor: TX len : 100
2023-02-03T09:24:44.037282Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:24:44.037312Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820e2ef8b895ee03259ee57850b1a1ed4aa7689bec352659200e63440303f9d0b81 },
    gas_used: 419377651718,
    events_root: None,
}
2023-02-03T09:24:44.037333Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 1
2023-02-03T09:24:44.037342Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::London::1
2023-02-03T09:24:44.037347Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:24:44.037351Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:26:04.591671Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:26:04.591692Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffaaffffffffffffffffbbffffffffffffff0009 },
    gas_used: 1100562893549,
    events_root: None,
}
2023-02-03T09:26:04.591707Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => London 2
2023-02-03T09:26:04.591712Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::London::2
2023-02-03T09:26:04.591715Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:26:04.591717Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:26:19.011706Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:26:19.011751Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200e1c6aac6663c379a52d9ccc7ba4757131020772d41447dfcf478cf9fb0c2bbf },
    gas_used: 262579344797,
    events_root: None,
}
2023-02-03T09:26:19.011783Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 0
2023-02-03T09:26:19.011791Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Merge::0
2023-02-03T09:26:19.011796Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:26:19.011801Z  INFO evm_eth_compliance::statetest::executor: TX len : 100
2023-02-03T09:26:50.623664Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:26:50.623687Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820e2ef8b895ee03259ee57850b1a1ed4aa7689bec352659200e63440303f9d0b81 },
    gas_used: 419377651718,
    events_root: None,
}
2023-02-03T09:26:50.623703Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 1
2023-02-03T09:26:50.623708Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Merge::1
2023-02-03T09:26:50.623711Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:26:50.623716Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:28:11.110861Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:28:11.110884Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5820ffffffffffffffffffffffffffaaffffffffffffffffbbffffffffffffff0009 },
    gas_used: 1100562893549,
    events_root: None,
}
2023-02-03T09:28:11.110899Z  INFO evm_eth_compliance::statetest::executor: Entering Post Block => Merge 2
2023-02-03T09:28:11.110904Z  INFO evm_eth_compliance::statetest::executor: Executing TestCase "loopMul"::Merge::2
2023-02-03T09:28:11.110907Z  INFO evm_eth_compliance::statetest::executor: Path : "loopMul.json"
2023-02-03T09:28:11.110910Z  INFO evm_eth_compliance::statetest::executor: TX len : 132
2023-02-03T09:28:25.528019Z  INFO evm_eth_compliance::statetest::executor: UC : "loopMul"
2023-02-03T09:28:25.528041Z  INFO evm_eth_compliance::statetest::executor: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200e1c6aac6663c379a52d9ccc7ba4757131020772d41447dfcf478cf9fb0c2bbf },
    gas_used: 262579344797,
    events_root: None,
}
2023-02-03T09:28:25.529616Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
████████████████████████████████████████████████████████████████████████████████████████████████████ 1/12023-02-03T09:28:25.529768Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:506.150602693s
=== Start ===
=== OK Status ===
Count :: 1
{
    "loopMul.json::loopMul": [
        "Istanbul | 0 | ExitCode { value: 0 }",
        "Istanbul | 1 | ExitCode { value: 0 }",
        "Istanbul | 2 | ExitCode { value: 0 }",
        "Berlin | 0 | ExitCode { value: 0 }",
        "Berlin | 1 | ExitCode { value: 0 }",
        "Berlin | 2 | ExitCode { value: 0 }",
        "London | 0 | ExitCode { value: 0 }",
        "London | 1 | ExitCode { value: 0 }",
        "London | 2 | ExitCode { value: 0 }",
        "Merge | 0 | ExitCode { value: 0 }",
        "Merge | 1 | ExitCode { value: 0 }",
        "Merge | 2 | ExitCode { value: 0 }",
    ],
}
=== KO Status ===
None
=== SKIP Status ===
None
=== End ===
```