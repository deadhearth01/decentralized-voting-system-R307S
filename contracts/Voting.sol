// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Voting {
    struct Candidate {
        string name;
        uint voteCount;
    }

    struct Voter {
        bool hasVoted;
        bool isRegistered;
    }

    struct AdminAction {
        string action;
        string dataHash;
        uint timestamp;
    }

    address public admin;
    Candidate[] public candidates;
    mapping(address => Voter) public voters;
    AdminAction[] public adminActions;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    function registerVoter(address _voter) public onlyAdmin {
        voters[_voter].isRegistered = true;
    }

    function addCandidate(string memory _name) public onlyAdmin {
        candidates.push(Candidate(_name, 0));
    }

    function updateCandidateName(uint _candidateId, string memory _newName) public onlyAdmin {
        require(_candidateId < candidates.length, "Invalid candidate ID");
        candidates[_candidateId].name = _newName;
    }

    function vote(uint _candidateId) public {
        require(voters[msg.sender].isRegistered, "Voter not registered");
        require(!voters[msg.sender].hasVoted, "Voter has already voted");
        require(_candidateId < candidates.length, "Invalid candidate ID");

        voters[msg.sender].hasVoted = true;
        candidates[_candidateId].voteCount += 1;
    }

    function getCandidateCount() public view returns (uint) {
        return candidates.length;
    }

    function getCandidate(uint _id) public view returns (string memory name, uint voteCount) {
        require(_id < candidates.length, "Invalid candidate ID");
        Candidate memory candidate = candidates[_id];
        return (candidate.name, candidate.voteCount);
    }

    function logAdminAction(string memory _action, string memory _dataHash) public onlyAdmin {
        adminActions.push(AdminAction(_action, _dataHash, block.timestamp));
    }

    function getAdminActionCount() public view returns (uint) {
        return adminActions.length;
    }

    function getAdminAction(uint _id) public view returns (string memory action, string memory dataHash, uint timestamp) {
        require(_id < adminActions.length, "Invalid action ID");
        AdminAction memory adminAction = adminActions[_id];
        return (adminAction.action, adminAction.dataHash, adminAction.timestamp);
    }
}