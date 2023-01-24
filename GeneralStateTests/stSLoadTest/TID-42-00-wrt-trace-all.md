> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stSLoadTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stSLoadTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, all use-cases passed.

> Execution Trace

```
2023-01-24T15:23:46.455201Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json", Total Files :: 1
2023-01-24T15:23:46.501613Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:23:46.501833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:23:46.501838Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:23:46.501895Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:23:46.501969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-24T15:23:46.501972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Frontier::0
2023-01-24T15:23:46.501975Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.501977Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.501979Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2496628,
    events_root: None,
}
2023-01-24T15:23:46.863337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Homestead 0
2023-01-24T15:23:46.863343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Homestead::0
2023-01-24T15:23:46.863345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863348Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2511574,
    events_root: None,
}
2023-01-24T15:23:46.863490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-24T15:23:46.863493Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::EIP150::0
2023-01-24T15:23:46.863495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863497Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.863602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-24T15:23:46.863604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::EIP158::0
2023-01-24T15:23:46.863606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863608Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.863708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-24T15:23:46.863710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Byzantium::0
2023-01-24T15:23:46.863712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863715Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.863814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-24T15:23:46.863817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Constantinople::0
2023-01-24T15:23:46.863819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.863913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.863920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-24T15:23:46.863922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::ConstantinopleFix::0
2023-01-24T15:23:46.863924Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.863926Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.863928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.864019Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.864026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:23:46.864029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Istanbul::0
2023-01-24T15:23:46.864031Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.864033Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.864034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.864124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.864131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:23:46.864133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Berlin::0
2023-01-24T15:23:46.864135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.864137Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.864139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.864228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.864235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:23:46.864238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::London::0
2023-01-24T15:23:46.864239Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.864242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.864243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.864334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.864341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:23:46.864343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadGasCost"::Merge::0
2023-01-24T15:23:46.864346Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stSLoadTest/sloadGasCost.json"
2023-01-24T15:23:46.864348Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:23:46.864350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:23:46.864439Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1595954,
    events_root: None,
}
2023-01-24T15:23:46.866052Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.83811ms
```