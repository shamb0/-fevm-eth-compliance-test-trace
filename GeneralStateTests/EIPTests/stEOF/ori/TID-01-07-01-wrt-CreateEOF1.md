> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json#L19

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T09:24:26.878384Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json", Total Files :: 1
2023-01-20T09:24:26.878850Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:26.999066Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.201731Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T09:24:39.201923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.202002Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-20T09:24:39.202028Z  WARN evm_eth_compliance::statetest::runner: Skipping Test EIP-3541: Contract code starting with the 0xEF byte is disallowed.
2023-01-20T09:24:39.202035Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 23, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceahoborpsf5x7brhzz4bnc5fawfeopez5i66gfxfysg7me2wslh3k
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.205351Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T09:24:39.205491Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.205534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceaouht6ygfqxw7vab7abrmb6ujmv623puy6wbqgt4di5mxaakxah2
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.208555Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T09:24:39.208723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.208766Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-20T09:24:39.208782Z  WARN evm_eth_compliance::statetest::runner: Skipping Test EIP-3541: Contract code starting with the 0xEF byte is disallowed.
2023-01-20T09:24:39.208788Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 218, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 220, 70, 60, 95, 134, 230, 77, 167, 148, 57, 129, 203, 169, 16, 22, 114, 213, 117, 83]) }
[DEBUG] getting cid: bafy2bzaceclwxs2hslku3547k2l4vii3fx4skwbrsbsfcru2kh3u5htyvwq6g
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.211848Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T09:24:39.212008Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.212061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-20T09:24:39.212083Z  WARN evm_eth_compliance::statetest::runner: Skipping Test EIP-3541: Contract code starting with the 0xEF byte is disallowed.
2023-01-20T09:24:39.212093Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 218, 122, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 5, 158, 185, 170, 5, 126, 190, 213, 91, 244, 103, 65, 236, 58, 54, 23, 90, 163, 232]) }
[DEBUG] getting cid: bafy2bzacebh44n2vje44fhix66hzimpmhgdui2psllululniiuinqv2xnziy2
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.216142Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-20T09:24:39.216306Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.216365Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [17, 34, 51, 68, 17, 34, 51, 68, 17, 34, 51, 68, 17, 34, 51, 68, 17, 34, 51, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([60, 213, 27, 33, 255, 147, 208, 24, 221, 249, 192, 33, 170, 243, 120, 65, 173, 130, 62, 118]) }
[DEBUG] getting cid: bafy2bzaced7ame43vxvm7bfew36pxvn3regwnmuwittfwcxm7on2pytualj5w
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.219565Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [205]
2023-01-20T09:24:39.219705Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.219751Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([52, 236, 47, 243, 10, 24, 163, 193, 208, 154, 15, 84, 169, 37, 75, 149, 162, 169, 2, 106]) }
[DEBUG] getting cid: bafy2bzacedrcsjyrroqyvx53ltehfrjpeb7pzqodp4obegcjwxzdqqymztziq
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.222724Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [206]
2023-01-20T09:24:39.222862Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.222909Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 96, 23, 27, 11, 254, 109, 105, 147, 242, 31, 205, 64, 122, 50, 192, 129, 171, 105, 157]) }
[DEBUG] getting cid: bafy2bzaceaajzlzvcockcgz6mky7siilmh7kjxuganlyhbj4hp3usgqzcmwhu
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.225875Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [207]
2023-01-20T09:24:39.226015Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:24:39.227269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T09:24:39.227330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::0
2023-01-20T09:24:39.227340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.227348Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.227355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 33, 241, 5, 85, 42, 148, 104, 19, 228, 132, 213, 55, 10, 65, 127, 237, 179, 76, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacea66xibi2feadu6jdaumm5kykyrjt72lfr2vylmxholv2uqmzwvgw
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-20T09:24:39.236102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24181518,
    events_root: None,
}
2023-01-20T09:24:39.236216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T09:24:39.236265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::1
2023-01-20T09:24:39.236273Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.236280Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.236286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [87, 205, 161, 205, 166, 75, 143, 84, 34, 208, 194, 59, 111, 208, 115, 132, 183, 246, 13, 186, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzacedj66o6fjsagdwcawzcq43feldke2wv47wj6cficjmhlcqrwewm3u
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.243077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19645868,
    events_root: None,
}
2023-01-20T09:24:39.243169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T09:24:39.243208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::3
2023-01-20T09:24:39.243215Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.243222Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.243228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [230, 51, 243, 36, 77, 62, 56, 92, 48, 211, 216, 78, 9, 147, 33, 136, 158, 224, 207, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzacebt5mtpadradt362aekjqeiugga55ldcg2wfzmueqlmvr62es6zq4
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.248767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 15963823,
    events_root: None,
}
2023-01-20T09:24:39.248852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T09:24:39.248901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::16
2023-01-20T09:24:39.248908Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.248916Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.248922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [229, 106, 40, 166, 43, 184, 223, 203, 12, 246, 170, 252, 172, 204, 33, 112, 40, 90, 145, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzacecs3iuq3qfpp3dxq6zox76u3ttmdeglyrchsd63aolpa4sevk5azy
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-20T09:24:39.256915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24361537,
    events_root: None,
}
2023-01-20T09:24:39.257021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T09:24:39.257053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::4
2023-01-20T09:24:39.257060Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.257067Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.257073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.260468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 9517856,
    events_root: None,
}
2023-01-20T09:24:39.260529Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T09:24:39.260559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::17
2023-01-20T09:24:39.260566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.260573Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.260578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.263771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8189160,
    events_root: None,
}
2023-01-20T09:24:39.263831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T09:24:39.263860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::5
2023-01-20T09:24:39.263867Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.263874Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.263880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.267321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8189160,
    events_root: None,
}
2023-01-20T09:24:39.267409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T09:24:39.267461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::7
2023-01-20T09:24:39.267469Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.267476Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.267483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.270060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4660075,
    events_root: None,
}
2023-01-20T09:24:39.270105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T09:24:39.270144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::11
2023-01-20T09:24:39.270151Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.270158Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.270164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.270983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.271009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T09:24:39.271038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::15
2023-01-20T09:24:39.271046Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.271053Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.271059Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.271844Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.271870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T09:24:39.271899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::2
2023-01-20T09:24:39.271906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.271913Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.271919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 153, 226, 78, 147, 58, 29, 216, 1, 16, 112, 187, 194, 7, 196, 12, 4, 109, 239, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
[DEBUG] getting cid: bafy2bzacedinkayun6tu3xrxjusa53gpqx22nrfzkpzhcpju3wbzbsscenk6o
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.277165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16010920,
    events_root: None,
}
2023-01-20T09:24:39.277231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T09:24:39.277262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::6
2023-01-20T09:24:39.277268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.277275Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.277281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.279913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5988772,
    events_root: None,
}
2023-01-20T09:24:39.279957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T09:24:39.279987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::8
2023-01-20T09:24:39.279994Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.280003Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.280009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.280820Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.280852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T09:24:39.280906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::9
2023-01-20T09:24:39.280919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.280929Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.280948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.282037Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.282081Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T09:24:39.282128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::10
2023-01-20T09:24:39.282140Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.282150Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.282159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.283227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.283278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T09:24:39.283326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::12
2023-01-20T09:24:39.283341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.283355Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.283369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.284493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.284542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T09:24:39.284586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::13
2023-01-20T09:24:39.284601Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.284615Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.284628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.285661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.285700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T09:24:39.285754Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::14
2023-01-20T09:24:39.285776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.285794Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.285807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.286805Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658216,
    events_root: None,
}
2023-01-20T09:24:39.286836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T09:24:39.286869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::18
2023-01-20T09:24:39.286877Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.286886Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.286894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [72, 219, 183, 194, 75, 250, 142, 180, 6, 180, 65, 34, 230, 38, 5, 246, 253, 15, 247, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
[DEBUG] getting cid: bafy2bzacedod4zzngcbor6oqqdstwz6x2cgmkkuz2ballcnv7yxo3pnl35mtg
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.292310Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16064094,
    events_root: None,
}
2023-01-20T09:24:39.292396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T09:24:39.292431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::19
2023-01-20T09:24:39.292439Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.292449Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.292457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.295128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5988772,
    events_root: None,
}
2023-01-20T09:24:39.295173Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T09:24:39.295205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::20
2023-01-20T09:24:39.295213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.295221Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.295229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [65, 25, 46, 203, 55, 47, 106, 231, 110, 60, 131, 228, 132, 228, 85, 147, 108, 180, 65, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
[DEBUG] getting cid: bafy2bzacecjraqvioqgc3chd4vitqsvancr4je2o2kti45ejlazazhv6zffkw
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.302800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17680286,
    events_root: None,
}
2023-01-20T09:24:39.302941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T09:24:39.303009Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::21
2023-01-20T09:24:39.303022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.303032Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.303041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.307010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8195573,
    events_root: None,
}
2023-01-20T09:24:39.307070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T09:24:39.307100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::22
2023-01-20T09:24:39.307108Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.307115Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.307122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [215, 137, 88, 125, 141, 187, 94, 254, 99, 26, 47, 222, 132, 87, 2, 96, 5, 179, 190, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
[DEBUG] getting cid: bafy2bzacecjraqvioqgc3chd4vitqsvancr4je2o2kti45ejlazazhv6zffkw
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.312642Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 16414914,
    events_root: None,
}
2023-01-20T09:24:39.312720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T09:24:39.312749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::23
2023-01-20T09:24:39.312756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.312763Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.312771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.316044Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8195573,
    events_root: None,
}
2023-01-20T09:24:39.316102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T09:24:39.316131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::24
2023-01-20T09:24:39.316139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.316147Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.316153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [115, 144, 110, 73, 95, 154, 166, 50, 45, 169, 208, 230, 184, 139, 14, 149, 139, 121, 159, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
[DEBUG] getting cid: bafy2bzacecjraqvioqgc3chd4vitqsvancr4je2o2kti45ejlazazhv6zffkw
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.322340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17677604,
    events_root: None,
}
2023-01-20T09:24:39.322446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T09:24:39.322500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateEOF1"::Shanghai::25
2023-01-20T09:24:39.322508Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.322515Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:24:39.322521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-20T09:24:39.325834Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8195573,
    events_root: None,
}
2023-01-20T09:24:39.328234Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/ori/CreateEOF1.json"
2023-01-20T09:24:39.328600Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.326860458s
```