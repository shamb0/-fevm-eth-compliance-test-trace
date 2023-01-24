> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stWalletTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stWalletTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution OK, all use-case passed.

> Execution Trace

```
2023-01-24T09:28:42.157864Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stWalletTest", Total Files :: 42
2023-01-24T09:28:42.158085Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:42.187638Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.187723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.187728Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Istanbul::0
2023-01-24T09:28:42.187731Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187734Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187735Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.187737Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Istanbul::0
2023-01-24T09:28:42.187739Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187741Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:42.187745Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Berlin::0
2023-01-24T09:28:42.187747Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187749Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:42.187752Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Berlin::0
2023-01-24T09:28:42.187754Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187756Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:42.187759Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::London::0
2023-01-24T09:28:42.187761Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187764Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:42.187767Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::London::0
2023-01-24T09:28:42.187769Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187771Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:42.187774Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Merge::0
2023-01-24T09:28:42.187775Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187778Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.187779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:42.187781Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstruction"::Merge::0
2023-01-24T09:28:42.187783Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.187785Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.188420Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstruction.json"
2023-01-24T09:28:42.188446Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.214581Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:42.214729Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.214832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.214840Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionOOG"::Istanbul::0
2023-01-24T09:28:42.214844Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.214848Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.214850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:42.214852Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionOOG"::Berlin::0
2023-01-24T09:28:42.214855Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.214859Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.214862Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:42.214865Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionOOG"::London::0
2023-01-24T09:28:42.214867Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.214871Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.214872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:42.214874Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionOOG"::Merge::0
2023-01-24T09:28:42.214876Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.214879Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.216048Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionOOG.json"
2023-01-24T09:28:42.216090Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:42.243196Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.243270Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.243275Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionPartial"::Istanbul::0
2023-01-24T09:28:42.243278Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243281Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.243283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:42.243284Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionPartial"::Berlin::0
2023-01-24T09:28:42.243287Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243289Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.243290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:42.243292Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionPartial"::London::0
2023-01-24T09:28:42.243293Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243296Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.243297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:42.243299Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "dayLimitConstructionPartial"::Merge::0
2023-01-24T09:28:42.243301Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243305Z  WARN evm_eth_compliance::statetest::runner: TX len : 2553
2023-01-24T09:28:42.243872Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitConstructionPartial.json"
2023-01-24T09:28:42.243898Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.269886Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:42.269995Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.269998Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:42.270062Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.270140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.270148Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitResetSpentToday"::Istanbul::0
2023-01-24T09:28:42.270151Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.270154Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:42.270156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:42.634141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1962358,
    events_root: None,
}
2023-01-24T09:28:42.634166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:42.634174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitResetSpentToday"::Berlin::0
2023-01-24T09:28:42.634176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.634179Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:42.634181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:42.634347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1962358,
    events_root: None,
}
2023-01-24T09:28:42.634355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:42.634358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitResetSpentToday"::London::0
2023-01-24T09:28:42.634360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.634363Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:42.634364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:42.634494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1962358,
    events_root: None,
}
2023-01-24T09:28:42.634501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:42.634504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitResetSpentToday"::Merge::0
2023-01-24T09:28:42.634506Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.634509Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:42.634510Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:42.634635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1962358,
    events_root: None,
}
2023-01-24T09:28:42.635975Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitResetSpentToday.json"
2023-01-24T09:28:42.636002Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:42.660513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:42.660623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.660626Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:42.660692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:42.660764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:42.660768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimit"::Istanbul::0
2023-01-24T09:28:42.660771Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:42.660774Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:42.660776Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.019093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1976567,
    events_root: None,
}
2023-01-24T09:28:43.019117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:43.019124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimit"::Berlin::0
2023-01-24T09:28:43.019127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:43.019130Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.019132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.019274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1976567,
    events_root: None,
}
2023-01-24T09:28:43.019281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:43.019283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimit"::London::0
2023-01-24T09:28:43.019285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:43.019288Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.019290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.019412Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1976567,
    events_root: None,
}
2023-01-24T09:28:43.019419Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:43.019421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimit"::Merge::0
2023-01-24T09:28:43.019423Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:43.019426Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.019427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.019549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1976567,
    events_root: None,
}
2023-01-24T09:28:43.021094Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimit.json"
2023-01-24T09:28:43.021123Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.045969Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:43.046072Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.046075Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:43.046136Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.046206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:43.046210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimitNoData"::Istanbul::0
2023-01-24T09:28:43.046213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.046216Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:43.046217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.392059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974734,
    events_root: None,
}
2023-01-24T09:28:43.392078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:43.392083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimitNoData"::Berlin::0
2023-01-24T09:28:43.392086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.392089Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:43.392091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.392226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974734,
    events_root: None,
}
2023-01-24T09:28:43.392232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:43.392235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimitNoData"::London::0
2023-01-24T09:28:43.392237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.392239Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:43.392241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.392362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974734,
    events_root: None,
}
2023-01-24T09:28:43.392369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:43.392371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "dayLimitSetDailyLimitNoData"::Merge::0
2023-01-24T09:28:43.392373Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.392376Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:43.392377Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.392497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1974734,
    events_root: None,
}
2023-01-24T09:28:43.393704Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/dayLimitSetDailyLimitNoData.json"
2023-01-24T09:28:43.393730Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.417524Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:43.417651Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.417654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:43.417708Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.417779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:43.417783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwner"::Istanbul::0
2023-01-24T09:28:43.417786Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.417789Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.417790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.782930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:43.782952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:43.782958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwner"::Berlin::0
2023-01-24T09:28:43.782961Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.782964Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.782965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.783104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:43.783112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:43.783115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwner"::London::0
2023-01-24T09:28:43.783118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.783120Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.783121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.783241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:43.783249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:43.783252Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwner"::Merge::0
2023-01-24T09:28:43.783254Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.783256Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.783258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:43.783384Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:43.785152Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwner.json"
2023-01-24T09:28:43.785179Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:43.810836Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:43.810950Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.810953Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:43.811006Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:43.811103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:43.811110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwnerAddMyself"::Istanbul::0
2023-01-24T09:28:43.811114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:43.811119Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:43.811121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.145049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:44.145071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:44.145077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwnerAddMyself"::Berlin::0
2023-01-24T09:28:44.145080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:44.145083Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:44.145085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.145248Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:44.145256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:44.145258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwnerAddMyself"::London::0
2023-01-24T09:28:44.145260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:44.145262Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:44.145264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.145386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:44.145393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:44.145395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedAddOwnerAddMyself"::Merge::0
2023-01-24T09:28:44.145397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:44.145400Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:44.145401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.145522Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1949107,
    events_root: None,
}
2023-01-24T09:28:44.147124Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedAddOwnerAddMyself.json"
2023-01-24T09:28:44.147152Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.172782Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:44.172896Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.172899Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:44.172952Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.173022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:44.173026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner"::Istanbul::0
2023-01-24T09:28:44.173029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.173033Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:44.173034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.514979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:44.515003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:44.515010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner"::Berlin::0
2023-01-24T09:28:44.515012Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.515016Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:44.515017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.515159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:44.515180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:44.515188Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner"::London::0
2023-01-24T09:28:44.515194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.515200Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:44.515205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.515334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:44.515350Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:44.515357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner"::Merge::0
2023-01-24T09:28:44.515366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.515373Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:44.515378Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.515506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:44.517196Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner.json"
2023-01-24T09:28:44.517226Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.543484Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:44.543602Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.543606Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:44.543660Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.543741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:44.543745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwnerNoArgument"::Istanbul::0
2023-01-24T09:28:44.543749Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.543752Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:44.543753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.886909Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1967958,
    events_root: None,
}
2023-01-24T09:28:44.886932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:44.886938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwnerNoArgument"::Berlin::0
2023-01-24T09:28:44.886941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.886944Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:44.886945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.887083Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1967958,
    events_root: None,
}
2023-01-24T09:28:44.887091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:44.887093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwnerNoArgument"::London::0
2023-01-24T09:28:44.887095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.887099Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:44.887100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.887223Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1967958,
    events_root: None,
}
2023-01-24T09:28:44.887230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:44.887232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwnerNoArgument"::Merge::0
2023-01-24T09:28:44.887234Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.887237Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T09:28:44.887238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:44.887358Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1967958,
    events_root: None,
}
2023-01-24T09:28:44.888739Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwnerNoArgument.json"
2023-01-24T09:28:44.888769Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:44.914109Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:44.914221Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.914224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:44.914277Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:44.914347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:44.914351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_fromNotOwner"::Istanbul::0
2023-01-24T09:28:44.914354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:44.914358Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:44.914359Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.279583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.279608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:45.279614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_fromNotOwner"::Berlin::0
2023-01-24T09:28:45.279618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:45.279621Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.279622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.279786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.279794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:45.279796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_fromNotOwner"::London::0
2023-01-24T09:28:45.279799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:45.279802Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.279803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.279935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.279942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:45.279944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_fromNotOwner"::Merge::0
2023-01-24T09:28:45.279946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:45.279949Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.279951Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.280076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.281367Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_fromNotOwner.json"
2023-01-24T09:28:45.281397Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.307365Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:45.307484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:45.307487Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:45.307555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:45.307643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:45.307649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_toIsOwner"::Istanbul::0
2023-01-24T09:28:45.307653Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.307656Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.307658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.644748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.644771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:45.644778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_toIsOwner"::Berlin::0
2023-01-24T09:28:45.644781Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.644784Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.644785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.644940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.644950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:45.644953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_toIsOwner"::London::0
2023-01-24T09:28:45.644956Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.644959Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.644961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.645108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.645116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:45.645119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeOwner_toIsOwner"::Merge::0
2023-01-24T09:28:45.645121Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.645124Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:45.645125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:45.645254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1971903,
    events_root: None,
}
2023-01-24T09:28:45.646645Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeOwner_toIsOwner.json"
2023-01-24T09:28:45.646675Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:45.672721Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:45.672901Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:45.672907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:45.672988Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:45.673086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:45.673095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo0"::Istanbul::0
2023-01-24T09:28:45.673098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:45.673101Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:45.673102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.045580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.045603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.045610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo0"::Berlin::0
2023-01-24T09:28:46.045613Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:46.045616Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.045617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.045783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.045790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.045793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo0"::London::0
2023-01-24T09:28:46.045795Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:46.045798Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.045799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.045925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.045933Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.045935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo0"::Merge::0
2023-01-24T09:28:46.045938Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:46.045940Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.045942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.046067Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.047771Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo0.json"
2023-01-24T09:28:46.047798Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.073999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.074120Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.074124Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:46.074179Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.074276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.074284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo1"::Istanbul::0
2023-01-24T09:28:46.074288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.074292Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.074294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.419533Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.419557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.419564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo1"::Berlin::0
2023-01-24T09:28:46.419566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.419570Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.419571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.419738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.419746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.419749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo1"::London::0
2023-01-24T09:28:46.419751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.419754Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.419755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.419883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.419890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.419893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo1"::Merge::0
2023-01-24T09:28:46.419895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.419897Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.419899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.420023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.421318Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo1.json"
2023-01-24T09:28:46.421344Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.449593Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.449709Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.449712Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:46.449767Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.449838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.449844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo2"::Istanbul::0
2023-01-24T09:28:46.449847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.449850Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.449852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.790240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.790260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.790267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo2"::Berlin::0
2023-01-24T09:28:46.790269Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.790273Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.790274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.790437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.790444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.790447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo2"::London::0
2023-01-24T09:28:46.790449Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.790452Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.790453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.790578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.790585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.790587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedChangeRequirementTo2"::Merge::0
2023-01-24T09:28:46.790590Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.790592Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.790594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:46.790719Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1960471,
    events_root: None,
}
2023-01-24T09:28:46.792194Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedChangeRequirementTo2.json"
2023-01-24T09:28:46.792222Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.817770Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.817876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.817950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.817955Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionCorrect"::Istanbul::0
2023-01-24T09:28:46.817958Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.817961Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.817963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.817965Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionCorrect"::Berlin::0
2023-01-24T09:28:46.817967Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.817969Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.817970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.817972Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionCorrect"::London::0
2023-01-24T09:28:46.817973Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.817976Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.817977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.817979Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionCorrect"::Merge::0
2023-01-24T09:28:46.817981Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.817983Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.818623Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionCorrect.json"
2023-01-24T09:28:46.818648Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.844429Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.844536Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.844609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.844613Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGas"::Istanbul::0
2023-01-24T09:28:46.844616Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.844620Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.844621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.844623Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGas"::Berlin::0
2023-01-24T09:28:46.844625Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.844627Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.844628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.844630Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGas"::London::0
2023-01-24T09:28:46.844632Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.844634Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.844636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.844637Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGas"::Merge::0
2023-01-24T09:28:46.844639Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.844642Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.845436Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGas.json"
2023-01-24T09:28:46.845468Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871488Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.871593Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.871667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.871671Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Istanbul::0
2023-01-24T09:28:46.871675Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871691Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.871695Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Istanbul::0
2023-01-24T09:28:46.871697Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871699Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.871702Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Berlin::0
2023-01-24T09:28:46.871704Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871707Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:46.871710Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Berlin::0
2023-01-24T09:28:46.871712Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871714Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.871717Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::London::0
2023-01-24T09:28:46.871719Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871721Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:46.871724Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::London::0
2023-01-24T09:28:46.871726Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871728Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.871731Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Merge::0
2023-01-24T09:28:46.871733Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871735Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:46.871738Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "multiOwnedConstructionNotEnoughGasPartial"::Merge::0
2023-01-24T09:28:46.871740Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871743Z  WARN evm_eth_compliance::statetest::runner: TX len : 2373
2023-01-24T09:28:46.871853Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedConstructionNotEnoughGasPartial.json"
2023-01-24T09:28:46.871875Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:46.895398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:46.895509Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.895512Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:46.895566Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:46.895636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:46.895639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerFalse"::Istanbul::0
2023-01-24T09:28:46.895642Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:46.895645Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:46.895646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.253652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.253676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:47.253684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerFalse"::Berlin::0
2023-01-24T09:28:47.253687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:47.253691Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.253692Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.253838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.253847Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:47.253849Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerFalse"::London::0
2023-01-24T09:28:47.253851Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:47.253854Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.253855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.253976Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.253986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:47.253988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerFalse"::Merge::0
2023-01-24T09:28:47.253991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:47.253994Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.253995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.254116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.255590Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerFalse.json"
2023-01-24T09:28:47.255616Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.282096Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:47.282244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:47.282249Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:47.282320Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:47.282404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:47.282411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerTrue"::Istanbul::0
2023-01-24T09:28:47.282415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.282418Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.282419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.627136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.627160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:47.627166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerTrue"::Berlin::0
2023-01-24T09:28:47.627169Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.627172Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.627173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.627309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.627319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:47.627321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerTrue"::London::0
2023-01-24T09:28:47.627324Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.627327Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.627328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.627448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.627456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:47.627460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedIsOwnerTrue"::Merge::0
2023-01-24T09:28:47.627462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.627465Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.627466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:47.627589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1932274,
    events_root: None,
}
2023-01-24T09:28:47.629068Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedIsOwnerTrue.json"
2023-01-24T09:28:47.629095Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:47.655290Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:47.655406Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:47.655411Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:47.655465Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:47.655538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:47.655543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner"::Istanbul::0
2023-01-24T09:28:47.655546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:47.655549Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:47.655550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.022921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1815383,
    events_root: None,
}
2023-01-24T09:28:48.022944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:48.022950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner"::Berlin::0
2023-01-24T09:28:48.022953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:48.022956Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.022957Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.023104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1815383,
    events_root: None,
}
2023-01-24T09:28:48.023112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:48.023114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner"::London::0
2023-01-24T09:28:48.023116Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:48.023119Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.023120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.023234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1815383,
    events_root: None,
}
2023-01-24T09:28:48.023242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:48.023244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner"::Merge::0
2023-01-24T09:28:48.023247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:48.023250Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.023251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.023370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1815383,
    events_root: None,
}
2023-01-24T09:28:48.024727Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner.json"
2023-01-24T09:28:48.024753Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.050085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:48.050192Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.050196Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:48.050271Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.050274Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:48.050352Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.050445Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:48.050453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwnerByNonOwner"::Istanbul::0
2023-01-24T09:28:48.050457Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.050461Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.050463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.397906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.397931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:48.397938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwnerByNonOwner"::Berlin::0
2023-01-24T09:28:48.397941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.397945Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.397946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.398100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.398111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:48.398113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwnerByNonOwner"::London::0
2023-01-24T09:28:48.398115Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.398117Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.398119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.398274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.398283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:48.398288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwnerByNonOwner"::Merge::0
2023-01-24T09:28:48.398291Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.398294Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.398296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.398455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.400853Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwnerByNonOwner.json"
2023-01-24T09:28:48.400908Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.427212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:48.427329Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.427332Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:48.427388Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.427462Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:48.427467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_mySelf"::Istanbul::0
2023-01-24T09:28:48.427470Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.427473Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.427474Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.799383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.799405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:48.799411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_mySelf"::Berlin::0
2023-01-24T09:28:48.799414Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.799418Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.799419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.799574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.799582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:48.799584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_mySelf"::London::0
2023-01-24T09:28:48.799586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.799589Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.799590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.799724Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.799731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:48.799734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_mySelf"::Merge::0
2023-01-24T09:28:48.799736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.799739Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.799740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:48.799861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:48.802116Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_mySelf.json"
2023-01-24T09:28:48.802150Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:48.828225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:48.828340Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.828343Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:48.828399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:48.828470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:48.828475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_ownerIsNotOwner"::Istanbul::0
2023-01-24T09:28:48.828478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:48.828481Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:48.828482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.170616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:49.170645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:49.170654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_ownerIsNotOwner"::Berlin::0
2023-01-24T09:28:49.170657Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:49.170661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.170664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.170835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:49.170847Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:49.170850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_ownerIsNotOwner"::London::0
2023-01-24T09:28:49.170852Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:49.170856Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.170858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.171012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:49.171021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:49.171024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRemoveOwner_ownerIsNotOwner"::Merge::0
2023-01-24T09:28:49.171027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:49.171032Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.171033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.171190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1937711,
    events_root: None,
}
2023-01-24T09:28:49.173446Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRemoveOwner_ownerIsNotOwner.json"
2023-01-24T09:28:49.173481Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.200108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:49.200228Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.200231Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:49.200288Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.200361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:49.200366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRevokeNothing"::Istanbul::0
2023-01-24T09:28:49.200369Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.200372Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.200373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.574312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1890055,
    events_root: None,
}
2023-01-24T09:28:49.574335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:49.574343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRevokeNothing"::Berlin::0
2023-01-24T09:28:49.574346Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.574350Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.574351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.574490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1890055,
    events_root: None,
}
2023-01-24T09:28:49.574498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:49.574501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRevokeNothing"::London::0
2023-01-24T09:28:49.574504Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.574507Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.574509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.574632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1890055,
    events_root: None,
}
2023-01-24T09:28:49.574640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:49.574643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "multiOwnedRevokeNothing"::Merge::0
2023-01-24T09:28:49.574646Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.574650Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.574652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.574774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1890055,
    events_root: None,
}
2023-01-24T09:28:49.576189Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/multiOwnedRevokeNothing.json"
2023-01-24T09:28:49.576216Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.601081Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:49.601191Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.601195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:49.601252Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.601254Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:49.601329Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.601403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:49.601408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletAddOwnerRemovePendingTransaction"::Istanbul::0
2023-01-24T09:28:49.601412Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.601416Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.601418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.940127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2119503,
    events_root: None,
}
2023-01-24T09:28:49.940149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:49.940155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletAddOwnerRemovePendingTransaction"::Berlin::0
2023-01-24T09:28:49.940158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.940161Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.940163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.940317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2119503,
    events_root: None,
}
2023-01-24T09:28:49.940324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:49.940327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletAddOwnerRemovePendingTransaction"::London::0
2023-01-24T09:28:49.940329Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.940332Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.940333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.940464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2119503,
    events_root: None,
}
2023-01-24T09:28:49.940470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:49.940473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletAddOwnerRemovePendingTransaction"::Merge::0
2023-01-24T09:28:49.940475Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.940478Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:49.940479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:49.940609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2119503,
    events_root: None,
}
2023-01-24T09:28:49.942017Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletAddOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.942047Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.966961Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:49.967064Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.967067Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:49.967119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.967121Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:49.967192Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:49.967261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:49.967265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeOwnerRemovePendingTransaction"::Istanbul::0
2023-01-24T09:28:49.967268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:49.967271Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:49.967273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.316114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2156667,
    events_root: None,
}
2023-01-24T09:28:50.316138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:50.316145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeOwnerRemovePendingTransaction"::Berlin::0
2023-01-24T09:28:50.316148Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:50.316151Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:50.316153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.316346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2156667,
    events_root: None,
}
2023-01-24T09:28:50.316354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:50.316356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeOwnerRemovePendingTransaction"::London::0
2023-01-24T09:28:50.316359Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:50.316362Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:50.316363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.316508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2156667,
    events_root: None,
}
2023-01-24T09:28:50.316515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:50.316518Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeOwnerRemovePendingTransaction"::Merge::0
2023-01-24T09:28:50.316520Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:50.316523Z  INFO evm_eth_compliance::statetest::runner: TX len : 68
2023-01-24T09:28:50.316525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.316672Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2156667,
    events_root: None,
}
2023-01-24T09:28:50.318133Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeOwnerRemovePendingTransaction.json"
2023-01-24T09:28:50.318160Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.344534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:50.344652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.344656Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:50.344728Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.344732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:50.344809Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.344906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:50.344914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeRequirementRemovePendingTransaction"::Istanbul::0
2023-01-24T09:28:50.344918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.344923Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:50.344925Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.686005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2141643,
    events_root: None,
}
2023-01-24T09:28:50.686028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:50.686034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeRequirementRemovePendingTransaction"::Berlin::0
2023-01-24T09:28:50.686038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.686041Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:50.686043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.686240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2141643,
    events_root: None,
}
2023-01-24T09:28:50.686250Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:50.686253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeRequirementRemovePendingTransaction"::London::0
2023-01-24T09:28:50.686255Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.686258Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:50.686259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.686429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2141643,
    events_root: None,
}
2023-01-24T09:28:50.686437Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:50.686440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletChangeRequirementRemovePendingTransaction"::Merge::0
2023-01-24T09:28:50.686442Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.686445Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:50.686446Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:50.686592Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2141643,
    events_root: None,
}
2023-01-24T09:28:50.688077Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletChangeRequirementRemovePendingTransaction.json"
2023-01-24T09:28:50.688107Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:50.714303Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:50.714432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.714437Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:50.714511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.714514Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:50.714616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:50.714718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:50.714727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletConfirm"::Istanbul::0
2023-01-24T09:28:50.714730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:50.714734Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:50.714736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.056180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2138238,
    events_root: None,
}
2023-01-24T09:28:51.056204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.056210Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletConfirm"::Berlin::0
2023-01-24T09:28:51.056213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:51.056216Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:51.056217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.056387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2138238,
    events_root: None,
}
2023-01-24T09:28:51.056396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.056399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletConfirm"::London::0
2023-01-24T09:28:51.056401Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:51.056403Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:51.056405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.056541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2138238,
    events_root: None,
}
2023-01-24T09:28:51.056550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.056553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletConfirm"::Merge::0
2023-01-24T09:28:51.056555Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:51.056557Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:51.056559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.056693Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2138238,
    events_root: None,
}
2023-01-24T09:28:51.057974Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConfirm.json"
2023-01-24T09:28:51.058000Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.083924Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.084061Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.084149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.084157Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Istanbul::0
2023-01-24T09:28:51.084161Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084165Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084167Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.084169Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Istanbul::0
2023-01-24T09:28:51.084172Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084175Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.084179Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Berlin::0
2023-01-24T09:28:51.084182Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084184Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.084188Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Berlin::0
2023-01-24T09:28:51.084191Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084194Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.084199Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::London::0
2023-01-24T09:28:51.084202Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084205Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.084209Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::London::0
2023-01-24T09:28:51.084211Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084214Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.084219Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Merge::0
2023-01-24T09:28:51.084221Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084224Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.084226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.084228Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstruction"::Merge::0
2023-01-24T09:28:51.084231Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.084234Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.085025Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstruction.json"
2023-01-24T09:28:51.085052Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111141Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.111244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.111316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.111320Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Istanbul::0
2023-01-24T09:28:51.111323Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111327Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.111330Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Istanbul::0
2023-01-24T09:28:51.111331Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111333Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.111337Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Berlin::0
2023-01-24T09:28:51.111338Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111341Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.111344Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Berlin::0
2023-01-24T09:28:51.111345Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111348Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.111351Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::London::0
2023-01-24T09:28:51.111352Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111355Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.111358Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::London::0
2023-01-24T09:28:51.111360Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111362Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.111365Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Merge::0
2023-01-24T09:28:51.111367Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111369Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.111371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.111372Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionOOG"::Merge::0
2023-01-24T09:28:51.111374Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.111376Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.112123Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionOOG.json"
2023-01-24T09:28:51.112147Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.138539Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.138644Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.138716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.138721Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionPartial"::Istanbul::0
2023-01-24T09:28:51.138724Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.138727Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.138728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.138730Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionPartial"::Berlin::0
2023-01-24T09:28:51.138732Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.138735Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.138736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.138738Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionPartial"::London::0
2023-01-24T09:28:51.138740Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.138742Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.138744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.138745Z  WARN evm_eth_compliance::statetest::runner: Skipping TestCase no valid actor "walletConstructionPartial"::Merge::0
2023-01-24T09:28:51.138747Z  WARN evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.138749Z  WARN evm_eth_compliance::statetest::runner: TX len : 4116
2023-01-24T09:28:51.139496Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletConstructionPartial.json"
2023-01-24T09:28:51.139519Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.165309Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.165412Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.165415Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:51.165482Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.165554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.165558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefault"::Istanbul::0
2023-01-24T09:28:51.165561Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.165564Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.165565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.546727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.546751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.546758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefault"::Berlin::0
2023-01-24T09:28:51.546761Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.546764Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.546765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.546904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.546911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.546914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefault"::London::0
2023-01-24T09:28:51.546917Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.546919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.546920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.547064Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.547073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.547078Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefault"::Merge::0
2023-01-24T09:28:51.547080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.547084Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.547086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.547240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.549053Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefault.json"
2023-01-24T09:28:51.549083Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.576054Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.576162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.576165Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:51.576233Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.576305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.576310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefaultWithOutValue"::Istanbul::0
2023-01-24T09:28:51.576313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.576316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.576318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.916320Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.916344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:51.916351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefaultWithOutValue"::Berlin::0
2023-01-24T09:28:51.916354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.916357Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.916358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.916503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.916510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:51.916512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefaultWithOutValue"::London::0
2023-01-24T09:28:51.916514Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.916517Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.916519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.916642Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.916650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:51.916652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletDefaultWithOutValue"::Merge::0
2023-01-24T09:28:51.916654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.916657Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T09:28:51.916658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:51.916778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1928602,
    events_root: None,
}
2023-01-24T09:28:51.918423Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletDefaultWithOutValue.json"
2023-01-24T09:28:51.918451Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:51.944474Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:51.944580Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.944584Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:51.944658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:51.944730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:51.944734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitMultiOwner"::Istanbul::0
2023-01-24T09:28:51.944737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:51.944740Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:51.944742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.279285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.279313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:52.279320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitMultiOwner"::Berlin::0
2023-01-24T09:28:52.279323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:52.279326Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.279328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.279528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.279539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:52.279541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitMultiOwner"::London::0
2023-01-24T09:28:52.279545Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:52.279547Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.279548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.279698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.279708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:52.279710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitMultiOwner"::Merge::0
2023-01-24T09:28:52.279712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:52.279715Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.279716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.279855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.281672Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitMultiOwner.json"
2023-01-24T09:28:52.281705Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.307804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:52.307914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:52.307918Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:52.307986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:52.308058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:52.308064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwner"::Istanbul::0
2023-01-24T09:28:52.308067Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.308071Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.308075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.671352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.671376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:52.671383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwner"::Berlin::0
2023-01-24T09:28:52.671386Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.671390Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.671392Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.671572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.671582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:52.671585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwner"::London::0
2023-01-24T09:28:52.671588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.671592Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.671594Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.671740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.671750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:52.671754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwner"::Merge::0
2023-01-24T09:28:52.671756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.671760Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.671762Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:52.671901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:52.673561Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwner.json"
2023-01-24T09:28:52.673588Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:52.699990Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:52.700104Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:52.700108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:52.700182Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:52.700257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:52.700263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwnerNew"::Istanbul::0
2023-01-24T09:28:52.700267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:52.700271Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:52.700273Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.036676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.036700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:53.036707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwnerNew"::Berlin::0
2023-01-24T09:28:53.036710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:53.036713Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.036714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.036895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.036904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:53.036906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwnerNew"::London::0
2023-01-24T09:28:53.036908Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:53.036911Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.036912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.037048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.037057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:53.037060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteOverDailyLimitOnlyOneOwnerNew"::Merge::0
2023-01-24T09:28:53.037062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:53.037065Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.037066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.037201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.038680Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteOverDailyLimitOnlyOneOwnerNew.json"
2023-01-24T09:28:53.038706Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.063885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:53.063987Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.063990Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:53.064059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.064130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:53.064135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteUnderDailyLimit"::Istanbul::0
2023-01-24T09:28:53.064138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.064141Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.064143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.413211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.413236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:53.413243Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteUnderDailyLimit"::Berlin::0
2023-01-24T09:28:53.413246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.413249Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.413250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.413423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.413432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:53.413435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteUnderDailyLimit"::London::0
2023-01-24T09:28:53.413437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.413440Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.413441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.413572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.413580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:53.413582Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletExecuteUnderDailyLimit"::Merge::0
2023-01-24T09:28:53.413585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.413587Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T09:28:53.413588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.413718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 2144989,
    events_root: None,
}
2023-01-24T09:28:53.415003Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletExecuteUnderDailyLimit.json"
2023-01-24T09:28:53.415029Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.440335Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:53.440443Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.440446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:53.440513Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.440584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:53.440589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKill"::Istanbul::0
2023-01-24T09:28:53.440592Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.440595Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:53.440596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.808508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:53.808528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:53.808535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKill"::Berlin::0
2023-01-24T09:28:53.808538Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.808540Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:53.808542Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.808717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:53.808724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:53.808728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKill"::London::0
2023-01-24T09:28:53.808730Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.808732Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:53.808733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.808873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:53.808880Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:53.808883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKill"::Merge::0
2023-01-24T09:28:53.808884Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.808888Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:53.808889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:53.809027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:53.810107Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKill.json"
2023-01-24T09:28:53.810134Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:53.834379Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:53.834484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.834487Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:53.834542Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.834544Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:53.834617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:53.834689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:53.834693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillNotByOwner"::Istanbul::0
2023-01-24T09:28:53.834696Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:53.834699Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:53.834701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.167336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.167357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:54.167363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillNotByOwner"::Berlin::0
2023-01-24T09:28:54.167366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:54.167369Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.167370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.167547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.167554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:54.167556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillNotByOwner"::London::0
2023-01-24T09:28:54.167558Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:54.167561Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.167562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.167711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.167718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:54.167721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillNotByOwner"::Merge::0
2023-01-24T09:28:54.167723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:54.167725Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.167726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.167869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.169242Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillNotByOwner.json"
2023-01-24T09:28:54.169269Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.194229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:54.194364Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:54.194368Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:54.194467Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:54.194570Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:54.194575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillToWallet"::Istanbul::0
2023-01-24T09:28:54.194579Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.194583Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.194585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.531082Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.531106Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:54.531112Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillToWallet"::Berlin::0
2023-01-24T09:28:54.531114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.531117Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.531119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.531333Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.531341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:54.531344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillToWallet"::London::0
2023-01-24T09:28:54.531346Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.531349Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.531351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.531492Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.531499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:54.531502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletKillToWallet"::Merge::0
2023-01-24T09:28:54.531504Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.531506Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.531508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.531648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2148007,
    events_root: None,
}
2023-01-24T09:28:54.533086Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletKillToWallet.json"
2023-01-24T09:28:54.533113Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.559272Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T09:28:54.559381Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:54.559385Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T09:28:54.559440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:54.559442Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T09:28:54.559516Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T09:28:54.559590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T09:28:54.559595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletRemoveOwnerRemovePendingTransaction"::Istanbul::0
2023-01-24T09:28:54.559598Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.559602Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.559603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.919841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2104515,
    events_root: None,
}
2023-01-24T09:28:54.919865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T09:28:54.919871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletRemoveOwnerRemovePendingTransaction"::Berlin::0
2023-01-24T09:28:54.919874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.919878Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.919880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.920038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2104515,
    events_root: None,
}
2023-01-24T09:28:54.920045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T09:28:54.920047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletRemoveOwnerRemovePendingTransaction"::London::0
2023-01-24T09:28:54.920049Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.920052Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.920054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.920193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2104515,
    events_root: None,
}
2023-01-24T09:28:54.920200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T09:28:54.920202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "walletRemoveOwnerRemovePendingTransaction"::Merge::0
2023-01-24T09:28:54.920205Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.920207Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-24T09:28:54.920209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T09:28:54.920347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2104515,
    events_root: None,
}
2023-01-24T09:28:54.921605Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stWalletTest/walletRemoveOwnerRemovePendingTransaction.json"
2023-01-24T09:28:54.921756Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 42 Files in Time:11.619031098s
```