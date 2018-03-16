DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)

if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) -D__STDC_LIMIT_MACROS"
endif

CROWCOIN_CONFIG_INCLUDES=-I$(builddir)/config
CROWCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

CROWCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
CROWCOIN_INCLUDES += -I$(srcdir)/univalue/include

LIBCROWCOIN_SERVER=libcrowcoin_server.a
LIBCROWCOIN_WALLET=libcrowcoin_wallet.a
LIBCROWCOIN_COMMON=libcrowcoin_common.a
LIBCROWCOIN_CLI=libcrowcoin_cli.a
LIBCROWCOIN_UTIL=libcrowcoin_util.a
LIBCROWCOIN_CRYPTO=crypto/libcrowcoin_crypto.a
LIBCROWCOINQT=qt/libcrowcoinqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBUNIVALUE=univalue/libunivalue.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
  
$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES = \
  crypto/libcrowcoin_crypto.a \
  libcrowcoin_util.a \
  libcrowcoin_common.a \
  libcrowcoin_server.a \
  libcrowcoin_cli.a
if ENABLE_WALLET
CROWCOIN_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += libcrowcoin_wallet.a
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += libcrowcoin_zmq.a
endif

if BUILD_CROWCOIN_LIBS
lib_LTLIBRARIES = libcrowcoinconsensus.la
LIBCROWCOIN_CONSENSUS=libcrowcoinconsensus.la
else
LIBCROWCOIN_CONSENSUS=
endif

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_CROWCOIND
  bin_PROGRAMS += crowcoind
endif

if BUILD_CROWCOIN_UTILS
  bin_PROGRAMS += crowcoin-cli crowcoin-tx
endif

.PHONY: FORCE check-symbols check-security
# crowcoin core #
CROWCOIN_CORE_H = \
  addrman.h \
  alert.h \
  amount.h \
  arith_uint256.h \
  base58.h \
  bloom.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  hash.h \
  httprpc.h \
  httpserver.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  main.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  netbase.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpcclient.h \
  rpcprotocol.h \
  rpcserver.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  serialize.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltime.h \
  validationinterface.h \
  version.h \
  versionbits.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libcrowcoin_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between crowcoind and crowcoin-qt
libcrowcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libcrowcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_server_a_SOURCES = \
  addrman.cpp \
  alert.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  main.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpcblockchain.cpp \
  rpcmining.cpp \
  rpcmisc.cpp \
  rpcnet.cpp \
  rpcrawtransaction.cpp \
  rpcserver.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(CROWCOIN_CORE_H)

if ENABLE_ZMQ
LIBCROWCOIN_ZMQ=libcrowcoin_zmq.a

libcrowcoin_zmq_a_CPPFLAGS = $(CROWCOIN_INCLUDES) $(ZMQ_CFLAGS)
libcrowcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between crowcoind and crowcoin-qt, but only linked
# when wallet enabled
libcrowcoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
libcrowcoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_wallet_a_SOURCES = \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(CROWCOIN_CORE_H)

# crypto primitives library
crypto_libcrowcoin_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_CONFIG_INCLUDES)
crypto_libcrowcoin_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libcrowcoin_crypto_a_SOURCES = \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

# common: shared between crowcoind, and crowcoin-qt and non-server tools
libcrowcoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
libcrowcoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  core_read.cpp \
  core_write.cpp \
  hash.cpp \
  key.cpp \
  keystore.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  $(CROWCOIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libcrowcoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
libcrowcoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_util_a_SOURCES = \
  support/pagelocker.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpcprotocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(CROWCOIN_CORE_H)

if GLIBC_BACK_COMPAT
libcrowcoin_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between crowcoin-cli and crowcoin-qt
libcrowcoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
libcrowcoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libcrowcoin_cli_a_SOURCES = \
  rpcclient.cpp \
  $(CROWCOIN_CORE_H)

nodist_libcrowcoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# crowcoind binary #
crowcoind_SOURCES = crowcoind.cpp
crowcoind_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
crowcoind_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crowcoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
crowcoind_SOURCES += crowcoind-res.rc
endif

crowcoind_LDADD = \
  $(LIBCROWCOIN_SERVER) \
  $(LIBCROWCOIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBCROWCOIN_UTIL) \
  $(LIBCROWCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

if ENABLE_ZMQ
crowcoind_LDADD += $(LIBCROWCOIN_ZMQ) $(ZMQ_LIBS)
endif

if ENABLE_WALLET
crowcoind_LDADD += libcrowcoin_wallet.a
endif

crowcoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)

# crowcoin-cli binary #
crowcoin_cli_SOURCES = crowcoin-cli.cpp
crowcoin_cli_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES) $(EVENT_CFLAGS)
crowcoin_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crowcoin_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
crowcoin_cli_SOURCES += crowcoin-cli-res.rc
endif

crowcoin_cli_LDADD = \
  $(LIBCROWCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBCROWCOIN_UTIL)

crowcoin_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# crowcoin-tx binary #
crowcoin_tx_SOURCES = crowcoin-tx.cpp
crowcoin_tx_CPPFLAGS = $(AM_CPPFLAGS) $(CROWCOIN_INCLUDES)
crowcoin_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crowcoin_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
crowcoin_tx_SOURCES += crowcoin-tx-res.rc
endif

crowcoin_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBCROWCOIN_COMMON) \
  $(LIBCROWCOIN_UTIL) \
  $(LIBCROWCOIN_CRYPTO) \
  $(LIBSECP256K1)

crowcoin_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# crowcoinconsensus library #
if BUILD_CROWCOIN_LIBS
include_HEADERS = script/crowcoinconsensus.h
libcrowcoinconsensus_la_SOURCES = \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/crowcoinconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libcrowcoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libcrowcoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libcrowcoinconsensus_la_LIBADD = $(LIBSECP256K1)
libcrowcoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_CROWCOIN_INTERNAL
libcrowcoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a
CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
