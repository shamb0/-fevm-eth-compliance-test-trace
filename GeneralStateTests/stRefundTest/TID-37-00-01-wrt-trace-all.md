> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stRefundTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stRefundTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases passed.

> Execution Trace

```
2023-01-25T07:52:12.421588Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_1.json", Total Files :: 1
2023-01-25T07:52:12.506698Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:12.506894Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:12.506897Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:12.506953Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:12.506955Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:12.507016Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:12.507085Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:12.507088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_1"::Istanbul::0
2023-01-25T07:52:12.507091Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_1.json"
2023-01-25T07:52:12.507094Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:12.507096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:12.861880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544960,
    events_root: None,
}
2023-01-25T07:52:12.861902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:12.861909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_1"::Berlin::0
2023-01-25T07:52:12.861912Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_1.json"
2023-01-25T07:52:12.861915Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:12.861917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:12.862031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544960,
    events_root: None,
}
2023-01-25T07:52:12.862037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:12.862040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_1"::London::0
2023-01-25T07:52:12.862042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_1.json"
2023-01-25T07:52:12.862044Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:12.862045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:12.862125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544960,
    events_root: None,
}
2023-01-25T07:52:12.862131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:12.862133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_1"::Merge::0
2023-01-25T07:52:12.862135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_1.json"
2023-01-25T07:52:12.862137Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:12.862139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:12.862217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1544960,
    events_root: None,
}
2023-01-25T07:52:12.863577Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.530387ms
2023-01-25T07:52:13.120170Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_2.json", Total Files :: 1
2023-01-25T07:52:13.184174Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:13.184380Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.184384Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:13.184444Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.184446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:13.184514Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.184605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:13.184610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_2"::Istanbul::0
2023-01-25T07:52:13.184613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_2.json"
2023-01-25T07:52:13.184617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:13.184619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:13.545431Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3448493,
    events_root: None,
}
2023-01-25T07:52:13.545454Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:13.545461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_2"::Berlin::0
2023-01-25T07:52:13.545464Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_2.json"
2023-01-25T07:52:13.545466Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:13.545468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:13.545615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2317195,
    events_root: None,
}
2023-01-25T07:52:13.545622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:13.545625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_2"::London::0
2023-01-25T07:52:13.545626Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_2.json"
2023-01-25T07:52:13.545629Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:13.545630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:13.545754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2317195,
    events_root: None,
}
2023-01-25T07:52:13.545761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:13.545763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50_2"::Merge::0
2023-01-25T07:52:13.545765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50_2.json"
2023-01-25T07:52:13.545767Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:13.545769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:13.545893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2317195,
    events_root: None,
}
2023-01-25T07:52:13.547405Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.730944ms
2023-01-25T07:52:13.805425Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50percentCap.json", Total Files :: 1
2023-01-25T07:52:13.835428Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:13.835659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.835664Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:13.835723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.835725Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:13.835787Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:13.835870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:13.835875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50percentCap"::Istanbul::0
2023-01-25T07:52:13.835878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50percentCap.json"
2023-01-25T07:52:13.835884Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:13.835886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.180084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3665741,
    events_root: None,
}
2023-01-25T07:52:14.180107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:14.180115Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50percentCap"::Berlin::0
2023-01-25T07:52:14.180118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50percentCap.json"
2023-01-25T07:52:14.180121Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.180123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.180318Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2609676,
    events_root: None,
}
2023-01-25T07:52:14.180326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:14.180329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50percentCap"::London::0
2023-01-25T07:52:14.180332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50percentCap.json"
2023-01-25T07:52:14.180336Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.180338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.180489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2609676,
    events_root: None,
}
2023-01-25T07:52:14.180498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:14.180501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund50percentCap"::Merge::0
2023-01-25T07:52:14.180504Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund50percentCap.json"
2023-01-25T07:52:14.180507Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.180509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.180661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2609676,
    events_root: None,
}
2023-01-25T07:52:14.182232Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.246105ms
2023-01-25T07:52:14.466348Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund600.json", Total Files :: 1
2023-01-25T07:52:14.506382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:14.506572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:14.506575Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:14.506628Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:14.506630Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:14.506688Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:14.506757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:14.506760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund600"::Istanbul::0
2023-01-25T07:52:14.506763Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund600.json"
2023-01-25T07:52:14.506765Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.506767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.880000Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2634435,
    events_root: None,
}
2023-01-25T07:52:14.880027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:14.880037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund600"::Berlin::0
2023-01-25T07:52:14.880041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund600.json"
2023-01-25T07:52:14.880044Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.880046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.880229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1727437,
    events_root: None,
}
2023-01-25T07:52:14.880238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:14.880242Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund600"::London::0
2023-01-25T07:52:14.880244Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund600.json"
2023-01-25T07:52:14.880247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.880249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.880375Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1727437,
    events_root: None,
}
2023-01-25T07:52:14.880384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:14.880387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund600"::Merge::0
2023-01-25T07:52:14.880389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund600.json"
2023-01-25T07:52:14.880392Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:14.880394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:14.880519Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1727437,
    events_root: None,
}
2023-01-25T07:52:14.882713Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.151162ms
2023-01-25T07:52:15.160730Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refundFF.json", Total Files :: 1
2023-01-25T07:52:15.189945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:15.190195Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:15.190200Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:15.190266Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:15.190268Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:15.190328Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:15.190410Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:15.190414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundFF"::Berlin::0
2023-01-25T07:52:15.190417Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundFF.json"
2023-01-25T07:52:15.190420Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:15.190421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:15.563339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2153251,
    events_root: None,
}
2023-01-25T07:52:15.563361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:15.563368Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundFF"::London::0
2023-01-25T07:52:15.563370Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundFF.json"
2023-01-25T07:52:15.563373Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:15.563374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:15.563471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035835,
    events_root: None,
}
2023-01-25T07:52:15.563476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:15.563479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundFF"::Merge::0
2023-01-25T07:52:15.563480Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundFF.json"
2023-01-25T07:52:15.563482Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:15.563484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:15.563546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035835,
    events_root: None,
}
2023-01-25T07:52:15.564940Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.611662ms
2023-01-25T07:52:15.822553Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refundMax.json", Total Files :: 1
2023-01-25T07:52:15.888340Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:15.888544Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:15.888548Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:15.888604Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:15.888678Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:15.888681Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundMax"::Berlin::0
2023-01-25T07:52:15.888684Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundMax.json"
2023-01-25T07:52:15.888687Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:15.888689Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.261772Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563055,
    events_root: None,
}
2023-01-25T07:52:16.261796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:16.261804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundMax"::London::0
2023-01-25T07:52:16.261807Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundMax.json"
2023-01-25T07:52:16.261810Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:16.261812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.261923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563055,
    events_root: None,
}
2023-01-25T07:52:16.261930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:16.261934Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundMax"::Merge::0
2023-01-25T07:52:16.261935Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundMax.json"
2023-01-25T07:52:16.261938Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:16.261940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.262029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563055,
    events_root: None,
}
2023-01-25T07:52:16.263878Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.701963ms
2023-01-25T07:52:16.548272Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refundResetFrontier.json", Total Files :: 1
2023-01-25T07:52:16.577628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:16.577824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:16.577828Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:16.577880Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:16.577882Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:16.577944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:16.578016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 0
2023-01-25T07:52:16.578019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundResetFrontier"::Frontier::0
2023-01-25T07:52:16.578022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundResetFrontier.json"
2023-01-25T07:52:16.578026Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-25T07:52:16.578027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.918470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8380931,
    events_root: None,
}
2023-01-25T07:52:16.918495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 1
2023-01-25T07:52:16.918502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundResetFrontier"::Frontier::1
2023-01-25T07:52:16.918505Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundResetFrontier.json"
2023-01-25T07:52:16.918508Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-25T07:52:16.918510Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.918771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5573542,
    events_root: None,
}
2023-01-25T07:52:16.918781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 2
2023-01-25T07:52:16.918783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundResetFrontier"::Frontier::2
2023-01-25T07:52:16.918786Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundResetFrontier.json"
2023-01-25T07:52:16.918788Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-25T07:52:16.918790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.919044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6332293,
    events_root: None,
}
2023-01-25T07:52:16.919054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Frontier 3
2023-01-25T07:52:16.919056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundResetFrontier"::Frontier::3
2023-01-25T07:52:16.919058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundResetFrontier.json"
2023-01-25T07:52:16.919061Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-25T07:52:16.919062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:16.919193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1826708,
    events_root: None,
}
2023-01-25T07:52:16.920799Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.577754ms
2023-01-25T07:52:17.194054Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSSTORE.json", Total Files :: 1
2023-01-25T07:52:17.236669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:17.236876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.236880Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:17.236937Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.237011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:17.237014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSSTORE"::Berlin::0
2023-01-25T07:52:17.237017Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSSTORE.json"
2023-01-25T07:52:17.237020Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:17.237021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:17.623923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530087,
    events_root: None,
}
2023-01-25T07:52:17.623946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:17.623954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSSTORE"::London::0
2023-01-25T07:52:17.623957Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSSTORE.json"
2023-01-25T07:52:17.623960Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:17.623961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:17.624083Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530087,
    events_root: None,
}
2023-01-25T07:52:17.624090Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:17.624092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSSTORE"::Merge::0
2023-01-25T07:52:17.624094Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSSTORE.json"
2023-01-25T07:52:17.624097Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-25T07:52:17.624099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:17.624185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530087,
    events_root: None,
}
2023-01-25T07:52:17.625872Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.527128ms
2023-01-25T07:52:17.904542Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json", Total Files :: 1
2023-01-25T07:52:17.934053Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:17.934248Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.934251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:17.934309Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.934311Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:17.934376Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.934378Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T07:52:17.934432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:17.934502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:17.934505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Istanbul::0
2023-01-25T07:52:17.934508Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:17.934511Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:17.934513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.296811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4277504,
    events_root: None,
}
2023-01-25T07:52:18.296835Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T07:52:18.296841Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Istanbul::1
2023-01-25T07:52:18.296844Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.296847Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.296849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.297059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4300034,
    events_root: None,
}
2023-01-25T07:52:18.297068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:18.297071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Berlin::0
2023-01-25T07:52:18.297074Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.297076Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.297078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.297267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4234998,
    events_root: None,
}
2023-01-25T07:52:18.297276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T07:52:18.297278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Berlin::1
2023-01-25T07:52:18.297280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.297283Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.297284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.297477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4300034,
    events_root: None,
}
2023-01-25T07:52:18.297486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:18.297488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::London::0
2023-01-25T07:52:18.297490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.297493Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.297494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.297678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4234998,
    events_root: None,
}
2023-01-25T07:52:18.297687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T07:52:18.297690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::London::1
2023-01-25T07:52:18.297692Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.297694Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.297696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.297883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4300034,
    events_root: None,
}
2023-01-25T07:52:18.297892Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:18.297895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Merge::0
2023-01-25T07:52:18.297897Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.297900Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.297901Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.298085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4234998,
    events_root: None,
}
2023-01-25T07:52:18.298094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T07:52:18.298096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refundSuicide50procentCap"::Merge::1
2023-01-25T07:52:18.298099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refundSuicide50procentCap.json"
2023-01-25T07:52:18.298101Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:18.298103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.298291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4300034,
    events_root: None,
}
2023-01-25T07:52:18.299879Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.251795ms
2023-01-25T07:52:18.565986Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA.json", Total Files :: 1
2023-01-25T07:52:18.609780Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:18.609971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:18.609974Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:18.610027Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:18.610029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:18.610089Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:18.610091Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T07:52:18.610142Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:18.610210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:18.610214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA"::Istanbul::0
2023-01-25T07:52:18.610216Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA.json"
2023-01-25T07:52:18.610219Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:18.610221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.964202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710201,
    events_root: None,
}
2023-01-25T07:52:18.964225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:18.964231Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA"::Berlin::0
2023-01-25T07:52:18.964234Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA.json"
2023-01-25T07:52:18.964237Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:18.964239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.964366Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710201,
    events_root: None,
}
2023-01-25T07:52:18.964374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:18.964377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA"::London::0
2023-01-25T07:52:18.964378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA.json"
2023-01-25T07:52:18.964381Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:18.964382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.964511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710201,
    events_root: None,
}
2023-01-25T07:52:18.964519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:18.964521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA"::Merge::0
2023-01-25T07:52:18.964523Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA.json"
2023-01-25T07:52:18.964526Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:18.964527Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:18.964633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710201,
    events_root: None,
}
2023-01-25T07:52:18.966140Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.8656ms
2023-01-25T07:52:19.246604Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json", Total Files :: 1
2023-01-25T07:52:19.276523Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:19.276722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.276726Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:19.276780Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.276783Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:19.276845Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.276848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T07:52:19.276903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.276974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:19.276977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_OOG"::Istanbul::0
2023-01-25T07:52:19.276980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json"
2023-01-25T07:52:19.276983Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:19.276985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:19.651697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710701,
    events_root: None,
}
2023-01-25T07:52:19.651720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:19.651726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_OOG"::Berlin::0
2023-01-25T07:52:19.651729Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json"
2023-01-25T07:52:19.651732Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:19.651733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:19.651855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710701,
    events_root: None,
}
2023-01-25T07:52:19.651863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:19.651866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_OOG"::London::0
2023-01-25T07:52:19.651868Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json"
2023-01-25T07:52:19.651871Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:19.651873Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:19.652011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710701,
    events_root: None,
}
2023-01-25T07:52:19.652018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:19.652022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_OOG"::Merge::0
2023-01-25T07:52:19.652024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_OOG.json"
2023-01-25T07:52:19.652026Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:19.652028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:19.652133Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1710701,
    events_root: None,
}
2023-01-25T07:52:19.653706Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.62243ms
2023-01-25T07:52:19.935957Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_notEnoughGasInCall.json", Total Files :: 1
2023-01-25T07:52:19.967639Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:19.967831Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.967835Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:19.967888Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.967890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:19.967957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.967959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-25T07:52:19.968013Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:19.968083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:19.968086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_notEnoughGasInCall"::Istanbul::0
2023-01-25T07:52:19.968089Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_notEnoughGasInCall.json"
2023-01-25T07:52:19.968092Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:19.968094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:20.354130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1709706,
    events_root: None,
}
2023-01-25T07:52:20.354151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:20.354160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_notEnoughGasInCall"::Berlin::0
2023-01-25T07:52:20.354163Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_notEnoughGasInCall.json"
2023-01-25T07:52:20.354167Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:20.354169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:20.354291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1709706,
    events_root: None,
}
2023-01-25T07:52:20.354300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:20.354303Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_notEnoughGasInCall"::London::0
2023-01-25T07:52:20.354306Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_notEnoughGasInCall.json"
2023-01-25T07:52:20.354310Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:20.354312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:20.354424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1709706,
    events_root: None,
}
2023-01-25T07:52:20.354432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:20.354436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallA_notEnoughGasInCall"::Merge::0
2023-01-25T07:52:20.354438Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallA_notEnoughGasInCall.json"
2023-01-25T07:52:20.354442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:20.354444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:20.354553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1709706,
    events_root: None,
}
2023-01-25T07:52:20.356284Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.926721ms
2023-01-25T07:52:20.637653Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json", Total Files :: 1
2023-01-25T07:52:20.673481Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:20.673674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:20.673678Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:20.673734Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:20.673736Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:20.673795Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:20.673866Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:20.673869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Istanbul::0
2023-01-25T07:52:20.673872Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:20.673875Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:20.673876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.039265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T07:52:21.039273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Istanbul::1
2023-01-25T07:52:21.039276Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039279Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.039446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:21.039449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Berlin::0
2023-01-25T07:52:21.039452Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039456Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039595Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.039602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T07:52:21.039605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Berlin::1
2023-01-25T07:52:21.039607Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039609Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.039730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:21.039733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::London::0
2023-01-25T07:52:21.039735Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039737Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.039848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T07:52:21.039850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::London::1
2023-01-25T07:52:21.039852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039855Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.039973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.039980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:21.039983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Merge::0
2023-01-25T07:52:21.039985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.039987Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.039989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.040092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.040101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T07:52:21.040104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideNoStorage"::Merge::1
2023-01-25T07:52:21.040106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideNoStorage.json"
2023-01-25T07:52:21.040109Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.040110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.040216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.041954Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.747551ms
2023-01-25T07:52:21.324341Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json", Total Files :: 1
2023-01-25T07:52:21.392519Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:21.392714Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:21.392717Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:21.392775Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:21.392777Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:21.392838Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:21.392910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:21.392913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Istanbul::0
2023-01-25T07:52:21.392916Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.392919Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.392920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.765210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T07:52:21.765217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Istanbul::1
2023-01-25T07:52:21.765220Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765223Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.765361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:21.765364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Berlin::0
2023-01-25T07:52:21.765367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765370Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765495Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.765502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T07:52:21.765505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Berlin::1
2023-01-25T07:52:21.765507Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765510Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.765629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:21.765631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::London::0
2023-01-25T07:52:21.765633Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765636Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.765750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T07:52:21.765752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::London::1
2023-01-25T07:52:21.765754Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765757Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.765875Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:21.765878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Merge::0
2023-01-25T07:52:21.765880Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.765882Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.765884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.765988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1703713,
    events_root: None,
}
2023-01-25T07:52:21.765995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T07:52:21.765997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideStorage"::Merge::1
2023-01-25T07:52:21.765999Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideStorage.json"
2023-01-25T07:52:21.766002Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:21.766003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:21.766112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1768749,
    events_root: None,
}
2023-01-25T07:52:21.767645Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.606033ms
2023-01-25T07:52:22.027591Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json", Total Files :: 1
2023-01-25T07:52:22.088245Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:22.088446Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.088449Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:22.088506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.088509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:22.088570Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.088643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:22.088646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Istanbul::0
2023-01-25T07:52:22.088649Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.088652Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.088654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877235,
    events_root: None,
}
2023-01-25T07:52:22.443069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-25T07:52:22.443076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Istanbul::1
2023-01-25T07:52:22.443078Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443082Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2007307,
    events_root: None,
}
2023-01-25T07:52:22.443241Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:22.443244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Berlin::0
2023-01-25T07:52:22.443246Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443250Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877235,
    events_root: None,
}
2023-01-25T07:52:22.443371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-25T07:52:22.443374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Berlin::1
2023-01-25T07:52:22.443377Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443379Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443499Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2007307,
    events_root: None,
}
2023-01-25T07:52:22.443507Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:22.443509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::London::0
2023-01-25T07:52:22.443511Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443514Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877235,
    events_root: None,
}
2023-01-25T07:52:22.443636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-25T07:52:22.443638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::London::1
2023-01-25T07:52:22.443640Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443643Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443766Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2007307,
    events_root: None,
}
2023-01-25T07:52:22.443774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:22.443776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Merge::0
2023-01-25T07:52:22.443779Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443781Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.443900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1877235,
    events_root: None,
}
2023-01-25T07:52:22.443909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-25T07:52:22.443911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_CallToSuicideTwice"::Merge::1
2023-01-25T07:52:22.443914Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_CallToSuicideTwice.json"
2023-01-25T07:52:22.443916Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-25T07:52:22.443918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:22.444049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2007307,
    events_root: None,
}
2023-01-25T07:52:22.445569Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.818699ms
2023-01-25T07:52:22.704362Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json", Total Files :: 1
2023-01-25T07:52:22.735015Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:22.735250Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.735254Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:22.735314Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.735316Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:22.735384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:22.735471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:22.735474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_NoOOG_1"::Istanbul::0
2023-01-25T07:52:22.735477Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json"
2023-01-25T07:52:22.735480Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:22.735482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.123478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.123500Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:23.123509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_NoOOG_1"::Berlin::0
2023-01-25T07:52:23.123512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json"
2023-01-25T07:52:23.123515Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.123517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.123624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.123632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:23.123635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_NoOOG_1"::London::0
2023-01-25T07:52:23.123638Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json"
2023-01-25T07:52:23.123641Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.123643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.123733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.123740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:23.123744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_NoOOG_1"::Merge::0
2023-01-25T07:52:23.123746Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_NoOOG_1.json"
2023-01-25T07:52:23.123749Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.123751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.123839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.125376Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:388.837598ms
2023-01-25T07:52:23.391913Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_OOG.json", Total Files :: 1
2023-01-25T07:52:23.421944Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:23.422143Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:23.422146Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:23.422201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:23.422203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:23.422263Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:23.422334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:23.422338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_OOG"::Istanbul::0
2023-01-25T07:52:23.422341Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_OOG.json"
2023-01-25T07:52:23.422344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.422346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.786642Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.786666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:23.786672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_OOG"::Berlin::0
2023-01-25T07:52:23.786675Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_OOG.json"
2023-01-25T07:52:23.786677Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.786679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.786802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.786810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:23.786813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_OOG"::London::0
2023-01-25T07:52:23.786816Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_OOG.json"
2023-01-25T07:52:23.786819Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.786822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.786922Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.786929Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:23.786932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_OOG"::Merge::0
2023-01-25T07:52:23.786933Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_OOG.json"
2023-01-25T07:52:23.786937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:23.786938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:23.787038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:23.789043Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.107227ms
2023-01-25T07:52:24.050226Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicide.json", Total Files :: 1
2023-01-25T07:52:24.086439Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:24.086638Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.086642Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:24.086699Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.086701Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:24.086760Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.086832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:24.086835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicide"::Istanbul::0
2023-01-25T07:52:24.086838Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicide.json"
2023-01-25T07:52:24.086842Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:24.086843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:24.465189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-01-25T07:52:24.465212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:24.465220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicide"::Berlin::0
2023-01-25T07:52:24.465222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicide.json"
2023-01-25T07:52:24.465225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:24.465227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:24.465315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:24.465321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:24.465323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicide"::London::0
2023-01-25T07:52:24.465325Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicide.json"
2023-01-25T07:52:24.465328Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:24.465329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:24.465399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:24.465405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:24.465407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicide"::Merge::0
2023-01-25T07:52:24.465409Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicide.json"
2023-01-25T07:52:24.465412Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:24.465414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:24.465481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:24.467200Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:379.052475ms
2023-01-25T07:52:24.739958Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json", Total Files :: 1
2023-01-25T07:52:24.770293Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:24.770529Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.770534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:24.770594Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.770596Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:24.770656Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:24.770731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:24.770734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicideOOG"::Istanbul::0
2023-01-25T07:52:24.770737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json"
2023-01-25T07:52:24.770740Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:24.770742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.123679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-01-25T07:52:25.123698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:25.123704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicideOOG"::Berlin::0
2023-01-25T07:52:25.123707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json"
2023-01-25T07:52:25.123710Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.123711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.123809Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:25.123815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:25.123818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicideOOG"::London::0
2023-01-25T07:52:25.123820Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json"
2023-01-25T07:52:25.123822Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.123824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.123892Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:25.123905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:25.123908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_TxToSuicideOOG"::Merge::0
2023-01-25T07:52:25.123909Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_TxToSuicideOOG.json"
2023-01-25T07:52:25.123912Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.123913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.123982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-25T07:52:25.125485Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.700273ms
2023-01-25T07:52:25.413856Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_changeNonZeroStorage.json", Total Files :: 1
2023-01-25T07:52:25.442877Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:25.443076Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:25.443080Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:25.443135Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:25.443137Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:25.443197Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:25.443269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:25.443273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_changeNonZeroStorage"::Istanbul::0
2023-01-25T07:52:25.443276Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_changeNonZeroStorage.json"
2023-01-25T07:52:25.443279Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.443280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.810489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453161,
    events_root: None,
}
2023-01-25T07:52:25.810510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:25.810517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_changeNonZeroStorage"::Berlin::0
2023-01-25T07:52:25.810520Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_changeNonZeroStorage.json"
2023-01-25T07:52:25.810522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.810524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.810636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1556747,
    events_root: None,
}
2023-01-25T07:52:25.810644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:25.810646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_changeNonZeroStorage"::London::0
2023-01-25T07:52:25.810649Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_changeNonZeroStorage.json"
2023-01-25T07:52:25.810652Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.810653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.810754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1556747,
    events_root: None,
}
2023-01-25T07:52:25.810762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:25.810765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_changeNonZeroStorage"::Merge::0
2023-01-25T07:52:25.810767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_changeNonZeroStorage.json"
2023-01-25T07:52:25.810772Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:25.810774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:25.810890Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1556747,
    events_root: None,
}
2023-01-25T07:52:25.812668Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.02702ms
2023-01-25T07:52:26.094663Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_getEtherBack.json", Total Files :: 1
2023-01-25T07:52:26.125573Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:26.125777Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.125781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:26.125837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.125839Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:26.125902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.125975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:26.125979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_getEtherBack"::Istanbul::0
2023-01-25T07:52:26.125982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_getEtherBack.json"
2023-01-25T07:52:26.125985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:26.125986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:26.502330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:26.502353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:26.502362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_getEtherBack"::Berlin::0
2023-01-25T07:52:26.502366Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_getEtherBack.json"
2023-01-25T07:52:26.502369Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:26.502370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:26.502470Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:26.502477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:26.502480Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_getEtherBack"::London::0
2023-01-25T07:52:26.502482Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_getEtherBack.json"
2023-01-25T07:52:26.502485Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:26.502486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:26.502571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:26.502577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:26.502579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_getEtherBack"::Merge::0
2023-01-25T07:52:26.502582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_getEtherBack.json"
2023-01-25T07:52:26.502584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-25T07:52:26.502586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:26.502669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1527056,
    events_root: None,
}
2023-01-25T07:52:26.504228Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.107672ms
2023-01-25T07:52:26.787211Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json", Total Files :: 1
2023-01-25T07:52:26.850552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:26.850759Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.850763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:26.850822Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.850824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:26.850888Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:26.850972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:26.850976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_multimpleSuicide"::Istanbul::0
2023-01-25T07:52:26.850979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json"
2023-01-25T07:52:26.850984Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:26.850986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.190596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000001 },
    gas_used: 7093697,
    events_root: None,
}
2023-01-25T07:52:27.190623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:27.190629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_multimpleSuicide"::Berlin::0
2023-01-25T07:52:27.190632Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json"
2023-01-25T07:52:27.190635Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.190636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.190717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.190725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:27.190727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_multimpleSuicide"::London::0
2023-01-25T07:52:27.190729Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json"
2023-01-25T07:52:27.190732Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.190735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.190817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.190824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:27.190826Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_multimpleSuicide"::Merge::0
2023-01-25T07:52:27.190828Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_multimpleSuicide.json"
2023-01-25T07:52:27.190831Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.190833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.190899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.192625Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.356795ms
2023-01-25T07:52:27.472048Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_singleSuicide.json", Total Files :: 1
2023-01-25T07:52:27.506700Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-25T07:52:27.506900Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:27.506904Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-25T07:52:27.506958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:27.506960Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-25T07:52:27.507036Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-25T07:52:27.507148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-25T07:52:27.507153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_singleSuicide"::Istanbul::0
2023-01-25T07:52:27.507156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_singleSuicide.json"
2023-01-25T07:52:27.507159Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.507161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.901665Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000000000000000001 },
    gas_used: 4622077,
    events_root: None,
}
2023-01-25T07:52:27.901695Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-25T07:52:27.901702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_singleSuicide"::Berlin::0
2023-01-25T07:52:27.901705Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_singleSuicide.json"
2023-01-25T07:52:27.901708Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.901709Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.901793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.901799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-25T07:52:27.901801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_singleSuicide"::London::0
2023-01-25T07:52:27.901804Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_singleSuicide.json"
2023-01-25T07:52:27.901806Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.901807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.901882Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.901890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-25T07:52:27.901892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "refund_singleSuicide"::Merge::0
2023-01-25T07:52:27.901894Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stRefundTest/refund_singleSuicide.json"
2023-01-25T07:52:27.901896Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-25T07:52:27.901897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-25T07:52:27.901968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-25T07:52:27.903546Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:395.279069ms
```