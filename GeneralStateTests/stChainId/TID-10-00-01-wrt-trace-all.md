> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stChainId

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stChainId \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases passed

> Execution Trace

```
2023-01-26T15:59:32.501208Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stChainId/chainId.json", Total Files :: 1
2023-01-26T15:59:32.558495Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:59:32.558662Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:59:32.558665Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:59:32.558723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:59:32.558795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:59:32.558798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainId"::Istanbul::0
2023-01-26T15:59:32.558801Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainId.json"
2023-01-26T15:59:32.558804Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:32.558806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:32.919510Z  INFO evm_eth_compliance::statetest::runner: UC : "chainId"
2023-01-26T15:59:32.919528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1541529,
    events_root: None,
}
2023-01-26T15:59:32.919538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:59:32.919543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainId"::Berlin::0
2023-01-26T15:59:32.919544Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainId.json"
2023-01-26T15:59:32.919547Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:32.919548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:32.919652Z  INFO evm_eth_compliance::statetest::runner: UC : "chainId"
2023-01-26T15:59:32.919656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1541529,
    events_root: None,
}
2023-01-26T15:59:32.919661Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:59:32.919663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainId"::London::0
2023-01-26T15:59:32.919664Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainId.json"
2023-01-26T15:59:32.919667Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:32.919668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:32.919754Z  INFO evm_eth_compliance::statetest::runner: UC : "chainId"
2023-01-26T15:59:32.919758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1541529,
    events_root: None,
}
2023-01-26T15:59:32.919763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:59:32.919765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainId"::Merge::0
2023-01-26T15:59:32.919767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainId.json"
2023-01-26T15:59:32.919769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:32.919771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:32.919855Z  INFO evm_eth_compliance::statetest::runner: UC : "chainId"
2023-01-26T15:59:32.919859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1541529,
    events_root: None,
}
2023-01-26T15:59:32.921524Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.372745ms
2023-01-26T15:59:33.201365Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stChainId/chainIdGasCost.json", Total Files :: 1
2023-01-26T15:59:33.232582Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T15:59:33.232745Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:59:33.232750Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T15:59:33.232808Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T15:59:33.232882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T15:59:33.232885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainIdGasCost"::Istanbul::0
2023-01-26T15:59:33.232887Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainIdGasCost.json"
2023-01-26T15:59:33.232891Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:33.232892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:33.607032Z  INFO evm_eth_compliance::statetest::runner: UC : "chainIdGasCost"
2023-01-26T15:59:33.607048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2508390,
    events_root: None,
}
2023-01-26T15:59:33.607059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T15:59:33.607064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainIdGasCost"::Berlin::0
2023-01-26T15:59:33.607066Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainIdGasCost.json"
2023-01-26T15:59:33.607069Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:33.607070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:33.607197Z  INFO evm_eth_compliance::statetest::runner: UC : "chainIdGasCost"
2023-01-26T15:59:33.607201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1606127,
    events_root: None,
}
2023-01-26T15:59:33.607206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T15:59:33.607208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainIdGasCost"::London::0
2023-01-26T15:59:33.607209Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainIdGasCost.json"
2023-01-26T15:59:33.607211Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:33.607213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:33.607299Z  INFO evm_eth_compliance::statetest::runner: UC : "chainIdGasCost"
2023-01-26T15:59:33.607302Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1606127,
    events_root: None,
}
2023-01-26T15:59:33.607307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T15:59:33.607309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "chainIdGasCost"::Merge::0
2023-01-26T15:59:33.607311Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stChainId/chainIdGasCost.json"
2023-01-26T15:59:33.607314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T15:59:33.607315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T15:59:33.607399Z  INFO evm_eth_compliance::statetest::runner: UC : "chainIdGasCost"
2023-01-26T15:59:33.607404Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1606127,
    events_root: None,
}
2023-01-26T15:59:33.608998Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.830577ms
```