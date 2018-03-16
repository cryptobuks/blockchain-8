Shared Libraries
================

## crowcoinconsensus

The purpose of this library is to make the verification functionality that is critical to Crowcoin's consensus available to other applications, e.g. to language bindings.

### API

The interface is defined in the C header `crowcoinconsensus.h` located in  `src/script/crowcoinconsensus.h`.

#### Version

`crowcoinconsensus_version` returns an `unsigned int` with the the API version *(currently at an experimental `0`)*.

#### Script Validation

`crowcoinconsensus_verify_script` returns an `int` with the status of the verification. It will be `1` if the input script correctly spends the previous output `scriptPubKey`.

##### Parameters
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `crowcoinconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

##### Script Flags
- `crowcoinconsensus_SCRIPT_FLAGS_VERIFY_NONE`
- `crowcoinconsensus_SCRIPT_FLAGS_VERIFY_P2SH` - Evaluate P2SH ([BIP16](https://github.com/crowcoin/bips/blob/master/bip-0016.mediawiki)) subscripts
- `crowcoinconsensus_SCRIPT_FLAGS_VERIFY_DERSIG` - Enforce strict DER ([BIP66](https://github.com/crowcoin/bips/blob/master/bip-0066.mediawiki)) compliance

##### Errors
- `crowcoinconsensus_ERR_OK` - No errors with input parameters *(see the return value of `crowcoinconsensus_verify_script` for the verification status)*
- `crowcoinconsensus_ERR_TX_INDEX` - An invalid index for `txTo`
- `crowcoinconsensus_ERR_TX_SIZE_MISMATCH` - `txToLen` did not match with the size of `txTo`
- `crowcoinconsensus_ERR_DESERIALIZE` - An error deserializing `txTo`

### Example Implementations
- [NCrowcoin](https://github.com/NicolasDorier/NCrowcoin/blob/master/NCrowcoin/Script.cs#L814) (.NET Bindings)
- [node-libcrowcoinconsensus](https://github.com/bitpay/node-libcrowcoinconsensus) (Node.js Bindings)
- [java-libcrowcoinconsensus](https://github.com/dexX7/java-libcrowcoinconsensus) (Java Bindings)
- [crowcoinconsensus-php](https://github.com/Bit-Wasp/crowcoinconsensus-php) (PHP Bindings)
