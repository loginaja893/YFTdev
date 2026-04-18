// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Orbital claw note: "lint-smoke / vinyl hinge / quiet servo"
    ---------------------------------------------------------
    YFTdev is a non-custodial claw-board: typed envelopes, delayed hull edits,
    and a notary lane for attestations. ETH is rejected at the door.
*/

contract YFTdev {
    // ---- claw errors (unique to this file) ----
    error YFTCLAW__VoidSender();
    error YFTCLAW__HullFrozen();
    error YFTCLAW__BadEpoch();
    error YFTCLAW__BadEnvelope();
    error YFTCLAW__NotSteward();
    error YFTCLAW__NotNotary();
    error YFTCLAW__NotWatchdog();
    error YFTCLAW__NotOwner();
    error YFTCLAW__DelayNotMet();
    error YFTCLAW__UnknownHullOp();
    error YFTCLAW__EtherRejected();
    error YFTCLAW__CapBreached();
    error YFTCLAW__NonceSpent();
    error YFTCLAW__MerkleBadProof();
    error YFTCLAW__SnapshotStale();
    error YFTCLAW__Ratelimit();
    error YFTCLAW__ZeroProbe();
    error YFTCLAW__BadScratch();

    // ---- claw events (unique) ----
    event ClawHullQueued(bytes32 indexed opTag, uint64 indexed eta, uint256 payload);
    event ClawHullApplied(bytes32 indexed opTag, uint64 at);
    event ClawEnvelopeSealed(bytes32 indexed envId, uint8 lane, bytes32 digest, address indexed author);
    event ClawNotaryInk(bytes32 indexed envId, bytes32 ink, uint64 at);
    event ClawScratchCommitted(bytes32 indexed scratchId, bytes32 head, uint64 at);
    event ClawPause(bool on);
    event ClawWatchBark(uint256 indexed code, bytes32 reason);
    event ClawMerkleRoot(bytes32 indexed root, uint64 at);
    event ClawRatelimitTuned(uint32 window, uint32 maxHits);

    // immutables (constructor-injected; mainstream access)
    address public immutable OWNER;
    address public immutable STEWARD;
    address public immutable NOTARY;
    address public immutable WATCHDOG;
    uint64 public immutable GENESIS_TS;
    uint256 public immutable CLAW_SEED;

    // fingerprint constants (non-authority)
    bytes32 private constant _CLAW_SALT_A = bytes32(0x341d66ba9c74d52b40322128d0c85f3f2309f70e4feb4e851f394473c1b4abc4);
    bytes32 private constant _CLAW_SALT_B = bytes32(0xf1480f8cccb419606527672ec8728c83fa3fd5fd04347bb1219fba4bf4a67e09);
    bytes32 public constant DOMAIN_VOUCH = keccak256("YFTdev.ClawVouch.v1");
    bytes32 public constant DOMAIN_SCRATCH = keccak256("YFTdev.ScratchLane.v1");

    bool public paused;
    uint64 public hullDelaySeconds;
    uint32 public rlWindow;
    uint32 public rlMaxHits;
    bytes32 public merkleRoot;
    uint64 public merkleVersion;

    struct HullOp {
        bytes32 opTag;
        uint64 eta;
        bool pending;
        uint256 payload;
    }

    struct Envelope {
        address author;
        uint8 lane;
        uint64 sealedAt;
        bytes32 digest;
        bytes32 notaryInk;
        bool inked;
    }

    struct Scratch {
        address author;
        bytes32 head;
        uint64 committedAt;
        uint256 nonce;
    }

    HullOp public hullOp;
    mapping(bytes32 => Envelope) public envelopes;
    mapping(bytes32 => Scratch) public scratches;
    mapping(address => uint64) private _rlBucket;
    mapping(address => uint32) private _rlCount;
    mapping(uint256 => bool) public nonceSpent;
