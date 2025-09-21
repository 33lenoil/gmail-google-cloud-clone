/*
 * This is a class for communication protocol between backend servers frontend and backend servers, and smtp server and backend servers.
 * It contains the message types and the structures for each message type, getters and setters for each message type,
 * as well as functions to serialize and deserialize the messages.
 */
#include "backendMessage.h"


backendMessage::backendMessage() {}
backendMessage::~backendMessage() {}

const std::map<backendMessage::messageType, std::string> backendMsgTypeStr = {
    {backendMessage::Req, "Req"},
    {backendMessage::Rsp, "Rsp"},
    {backendMessage::Redir, "Redir"},
    {backendMessage::Notify, "Notify"},
    {backendMessage::Ack, "Ack"},
    {backendMessage::CP, "CP"},
    {backendMessage::CPAck, "CPAck"},
    {backendMessage::Assign, "Assign"},
    {backendMessage::Shutdown, "Shutdown"},
    {backendMessage::Restart, "Restart"},
    {backendMessage::Ping, "Ping"},
    {backendMessage::Append, "Append"},
    {backendMessage::LogFileReq, "LogFileReq"},
    {backendMessage::LogFileRsp, "LogFileRsp"},
    {backendMessage::LogEntryReq, "LogEntryReq"},
    {backendMessage::LogEntryRsp, "LogEntryRsp"},
    {backendMessage::DataFileReq, "DataFileReq"},
    {backendMessage::DataFileRsp, "DataFileRsp"},
    {backendMessage::RecoveryDone, "RecoveryDone"},
    {backendMessage::GetInfoReq, "GetInfoReq"},
    {backendMessage::GetInfoRsp, "GetInfoRsp"},
};

backendMessage::backendMessage(backendMessage::messageType msgType,
                                std::string msgId, uint16_t isEnd) {
    this->msgType = msgType;
    this->msgId = msgId;
    this->isEnd = isEnd;
}

static void serializeStr(std::string str, std::vector<char>& buf) {
    uint32_t len = htonl(static_cast<uint32_t> (str.length()));
    buf.insert(buf.end(), reinterpret_cast<char*>(&len), reinterpret_cast<char*>(&len) + sizeof(uint32_t));
    buf.insert(buf.end(), str.begin(), str.end());
}

static std::string deserializeStr(char*& buffer) {
    uint32_t len = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    buffer += sizeof(uint32_t);
    std::string str(buffer, buffer + len);
    buffer += len;
    return str;
}

void backendMessage::ReqMsg::printMsg() const {
    std::cout << "Table Name: " << tableName << std::endl;
    std::cout << "Row Name: " << rowName << std::endl;
    std::cout << "Column Name: " << colName << std::endl;
    std::cout << "Match Value: " << matchVal << std::endl;
    std::cout << "New Value: " << newVal << std::endl;
}

void backendMessage::ReqMsg::serialize(std::vector<char>& buffer) const {
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&this->reqType), 
                reinterpret_cast<const char*>(&this->reqType) + sizeof(this->reqType));
    serializeStr(this->tableName, buffer);
    serializeStr(this->rowName, buffer);
    serializeStr(this->colName, buffer);
    serializeStr(this->matchVal, buffer);
    serializeStr(this->newVal, buffer);
}

void backendMessage::ReqMsg::deserialize(char*& buffer) {
    this->reqType = static_cast<requestType> (*reinterpret_cast<char*>(buffer));
    buffer += sizeof(this->reqType);
    this->tableName = deserializeStr(buffer);
    this->rowName = deserializeStr(buffer);
    this->colName = deserializeStr(buffer);
    this->matchVal = deserializeStr(buffer);
    this->newVal = deserializeStr(buffer);
}

size_t  backendMessage::ReqMsg::getSerializedSize() const {
    return sizeof(reqType) + sizeof(uint32_t) + tableName.length() + 
            sizeof(uint32_t) + rowName.length() + sizeof(uint32_t) + colName.length() + 
            sizeof(uint32_t) + matchVal.length() + sizeof(uint32_t) + newVal.length();
}

void backendMessage::RspMsg::printMsg() const {
    std::cout << "Content: " << content << std::endl;
}

void backendMessage::RspMsg::serialize(std::vector<char>& buffer) const {
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&this->status), 
                reinterpret_cast<const char*>(&this->status) + sizeof(this->status));
    serializeStr(this->content, buffer);
}

void backendMessage::RspMsg::deserialize(char*& buffer) {
    this->status = static_cast<responseType> (*reinterpret_cast<char*>(buffer));
    buffer += sizeof(this->status);
    this->content = deserializeStr(buffer);
}

size_t  backendMessage::RspMsg::getSerializedSize() const {
    return sizeof(status) + sizeof(uint32_t) + content.length();
}

void backendMessage::RedirMsg::printMsg() const {
    std::cout << "IP Port: " << ipPort << std::endl;
}

void backendMessage::RedirMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->ipPort, buffer);
}

void backendMessage::RedirMsg::deserialize(char*& buffer) {
    this->ipPort = deserializeStr(buffer);
}

size_t backendMessage::RedirMsg::getSerializedSize() const {
    return sizeof(uint32_t) + ipPort.length();
}

void backendMessage::NotifyMsg::printMsg() const {
    std::cout << "Request ID: " << reqId << std::endl;
    std::cout << "Source ID: " << sourceId << std::endl;
    std::cout << "Table Name: " << tableName << std::endl;
    std::cout << "Row Name: " << rowName << std::endl;
    std::cout << "Column Name: " << colName << std::endl;
    std::cout << "New Value: " << newVal << std::endl;
}

void backendMessage::NotifyMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->reqId, buffer);
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&this->reqType), 
                reinterpret_cast<const char*>(&this->reqType) + sizeof(this->reqType));
    serializeStr(this->sourceId, buffer);
    serializeStr(this->tableName, buffer);
    serializeStr(this->rowName, buffer);
    serializeStr(this->colName, buffer);
    serializeStr(this->newVal, buffer);
}

void backendMessage::NotifyMsg::deserialize(char*& buffer) {
    this->reqId = deserializeStr(buffer);
    this->reqType = static_cast<requestType> (*reinterpret_cast<char*>(buffer));
    buffer += sizeof(this->reqType);
    this->sourceId = deserializeStr(buffer);
    this->tableName = deserializeStr(buffer);
    this->rowName = deserializeStr(buffer);
    this->colName = deserializeStr(buffer);
    this->newVal = deserializeStr(buffer);
}

size_t backendMessage::NotifyMsg::getSerializedSize() const {
    return sizeof(uint32_t) + reqId.length() + sizeof(reqType) + 
            sizeof(uint32_t) + sourceId.length() + sizeof(uint32_t) + tableName.length() + 
            sizeof(uint32_t) + rowName.length() + sizeof(uint32_t) + colName.length() + 
            sizeof(uint32_t) + newVal.length();
}

void backendMessage::AckMsg::printMsg() const {
    std::cout << "Request ID: " << reqId << std::endl;
}

void backendMessage::AckMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->reqId, buffer);
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&this->status), 
            reinterpret_cast<const char*>(&this->status) + sizeof(this->status));
}

void backendMessage::AckMsg::deserialize(char*& buffer) {
    this->reqId = deserializeStr(buffer);
    this->status = static_cast<responseType> (*reinterpret_cast<char*>(buffer));
    buffer += sizeof(this->status);
}

size_t backendMessage::AckMsg::getSerializedSize() const {
    return sizeof(uint32_t) + reqId.length() + sizeof(status);
}

void backendMessage::CPMsg::printMsg() const {
    std::cout << "Checkpoint Version: " << cpVersion << std::endl;
}

void backendMessage::CPMsg::serialize(std::vector<char>& buffer) const {
    uint32_t cpVersion = htonl(this->cpVersion);
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&cpVersion), 
                reinterpret_cast<char*>(&cpVersion) + sizeof(uint32_t));
}

void backendMessage::CPMsg::deserialize(char*& buffer) {
    this->cpVersion = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    buffer += sizeof(uint32_t);
}

size_t backendMessage::CPMsg::getSerializedSize() const {
    return sizeof(uint32_t);
}

void backendMessage::CPAckMsg::serialize(std::vector<char>& buffer) const {
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&this->status), 
            reinterpret_cast<const char*>(&this->status) + sizeof(this->status));
}

void backendMessage::CPAckMsg::deserialize(char*& buffer) {
    this->status = static_cast<responseType> (*reinterpret_cast<char*>(buffer));
    buffer += sizeof(this->status);
}

size_t backendMessage::CPAckMsg::getSerializedSize() const {
    return sizeof(status);
}

void backendMessage::AssignMsg::printMsg() const {
    std::cout << "Role: " << role << std::endl;
    std::cout << "Primary IP Port: " << primaryIpPort << std::endl;
    std::cout << "Secondary IP Ports: " << std::endl;
    for (auto& ipPort : secondaryIpPort) {
        std::cout << ipPort << std::endl;
    }
    std::cout << "Letter Key Range: " << letterKeyRange.first << " - " << letterKeyRange.second << std::endl;
    std::cout << "Number Key Range: " << numKeyRange.first << " - " << numKeyRange.second << std::endl;
    std::cout << "Number of Secondaries Ready: " << numSecondariesReady << std::endl;
}

void backendMessage::AssignMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->role, buffer);
    serializeStr(this->primaryIpPort, buffer);
    uint32_t numSecIpPort = htonl(static_cast<uint32_t> (this->secondaryIpPort.size()));
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&numSecIpPort), 
                reinterpret_cast<char*>(&numSecIpPort) + sizeof(uint32_t));
    for (auto it = secondaryIpPort.begin(); it != secondaryIpPort.end(); it++){
        serializeStr(*it, buffer);
    }
    buffer.insert(buffer.end(), const_cast<char*>(&letterKeyRange.first), 
                const_cast<char*>(&letterKeyRange.first) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&letterKeyRange.second),
                const_cast<char*>(&letterKeyRange.second) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&numKeyRange.first),
                const_cast<char*>(&numKeyRange.first) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&numKeyRange.second),
                const_cast<char*>(&numKeyRange.second) + sizeof(char));
    int numSecsReady = htons(static_cast<int> (this->numSecondariesReady));
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&numSecsReady), 
                reinterpret_cast<char*>(&numSecsReady) + sizeof(int));
}

void backendMessage::AssignMsg::deserialize(char*& buffer) {
    this->role = deserializeStr(buffer);
    this->primaryIpPort = deserializeStr(buffer);
    uint32_t numSecIpPort = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    buffer += sizeof(uint32_t);
    for (uint32_t i = 0; i < numSecIpPort; i++) {
        std::string str = deserializeStr(buffer);
        this->secondaryIpPort.push_back(str);
    }
    this->letterKeyRange.first = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->letterKeyRange.second = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->numKeyRange.first = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->numKeyRange.second = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->numSecondariesReady = ntohs(*reinterpret_cast<int*>(buffer));
    buffer += sizeof(int);
}

size_t backendMessage::AssignMsg::getSerializedSize() const {
    size_t size = sizeof(uint32_t) + role.length() + sizeof(uint32_t) + primaryIpPort.length() + sizeof(uint32_t);
    for (auto it = secondaryIpPort.begin(); it != secondaryIpPort.end(); it++){
        size += sizeof(uint32_t) + it->length();
    }
    size += sizeof(char) + sizeof(char) + sizeof(char) + sizeof(char);
    size += sizeof(int);
    return size;
}

void backendMessage::ShutdownMsg::printMsg() const {
    std::cout << "Shutdown Message: " << shutdownMsg << std::endl;
}

void backendMessage::ShutdownMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->shutdownMsg, buffer);
}

void backendMessage::ShutdownMsg::deserialize(char*& buffer) {
    this->shutdownMsg = deserializeStr(buffer);
}

size_t backendMessage::ShutdownMsg::getSerializedSize() const {
    return sizeof(uint32_t) + shutdownMsg.length();
}

void backendMessage::RestartMsg::printMsg() const {
    std::cout << "Restart Message: " << restartMsg << std::endl;
}

void backendMessage::RestartMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->restartMsg, buffer);
}

void backendMessage::RestartMsg::deserialize(char*& buffer) {
    this->restartMsg = deserializeStr(buffer);
}

size_t backendMessage::RestartMsg::getSerializedSize() const {
    return sizeof(uint32_t) + restartMsg.length();
}

void backendMessage::PingMsg::printMsg() const {
    std::cout << "has key range: " << hasKeyRange << std::endl;
    std::cout << "num key range: " << numKeyRange.first << " - " << numKeyRange.second << std::endl;
    std::cout << "letter key range: " << letterKeyRange.first << " - " << letterKeyRange.second << std::endl;
}

void backendMessage::PingMsg::serialize(std::vector<char>& buffer) const {
    buffer.insert(buffer.end(), const_cast<char*>(&hasKeyRange), 
                const_cast<char*>(&hasKeyRange) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&numKeyRange.first), 
                const_cast<char*>(&numKeyRange.first) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&numKeyRange.second), 
                const_cast<char*>(&numKeyRange.second) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&letterKeyRange.first), 
                const_cast<char*>(&letterKeyRange.first) + sizeof(char));
    buffer.insert(buffer.end(), const_cast<char*>(&letterKeyRange.second), 
                const_cast<char*>(&letterKeyRange.second) + sizeof(char));
}

void backendMessage::PingMsg::deserialize(char*& buffer) {
    this->hasKeyRange = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->numKeyRange.first = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->numKeyRange.second = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->letterKeyRange.first = *const_cast<char*>(buffer);
    buffer += sizeof(char);
    this->letterKeyRange.second = *const_cast<char*>(buffer);
    buffer += sizeof(char);
}

size_t backendMessage::PingMsg::getSerializedSize() const {
    return sizeof(char) + sizeof(char) + sizeof(char) + sizeof(char) + sizeof(char);
}

void backendMessage::AppendMsg::printMsg() const {
    std::cout << "Table Name: " << tableName << std::endl;
    std::cout << "Row Name: " << rowName << std::endl;
    std::cout << "Column Name: " << colName << std::endl;
    std::cout << "Append Message: " << appendMsg << std::endl;
}

void backendMessage::AppendMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->tableName, buffer);
    serializeStr(this->rowName, buffer);
    serializeStr(this->colName, buffer);
    serializeStr(this->appendMsg, buffer);
}

void backendMessage::AppendMsg::deserialize(char*& buffer) {
    this->tableName = deserializeStr(buffer);
    this->rowName = deserializeStr(buffer);
    this->colName = deserializeStr(buffer);
    this->appendMsg = deserializeStr(buffer);
}

size_t backendMessage::AppendMsg::getSerializedSize() const {
    return sizeof(uint32_t) + tableName.length() + sizeof(uint32_t) + rowName.length() + 
            sizeof(uint32_t) + colName.length() + sizeof(uint32_t) + appendMsg.length();
}

void backendMessage::LogFileReqMsg::printMsg() const {
    std::cout << "Worker ID: " << workerId << std::endl;
}

void backendMessage::LogFileReqMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->workerId, buffer);
}

void backendMessage::LogFileReqMsg::deserialize(char*& buffer) {
    this->workerId = deserializeStr(buffer);
}

size_t backendMessage::LogFileReqMsg::getSerializedSize() const {
    return sizeof(uint32_t) + workerId.length();
}

void backendMessage::LogFileRspMsg::printMsg() const {
    std::cout << "Checkpoint Version: " << cpVersion << std::endl;
}

void backendMessage::LogFileRspMsg::serialize(std::vector<char>& buffer) const {
    uint32_t cpVersion = htonl(this->cpVersion);
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&cpVersion), 
                reinterpret_cast<char*>(&cpVersion) + sizeof(uint32_t));
}

void backendMessage::LogFileRspMsg::deserialize(char*& buffer) {
    this->cpVersion = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    buffer += sizeof(uint32_t);
}

size_t backendMessage::LogFileRspMsg::getSerializedSize() const {
    return sizeof(uint32_t);
}

void backendMessage::LogEntryReqMsg::printMsg() const {
    std::cout << "Worker ID: " << workerId << std::endl;
    std::cout << "Offset: " << offset << std::endl;
}

void backendMessage::LogEntryReqMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->workerId, buffer);
    serializeStr(this->offset, buffer);
}

void backendMessage::LogEntryReqMsg::deserialize(char*& buffer) {
    this->workerId = deserializeStr(buffer);
    this->offset = deserializeStr(buffer);
}

size_t backendMessage::LogEntryReqMsg::getSerializedSize() const {
    return sizeof(uint32_t) + workerId.length() + sizeof(uint32_t) + offset.length();
}

void backendMessage::LogEntryRspMsg::printMsg() const {
    std::cout << "Log File Size: " << logFileSize << std::endl;
    std::cout << "Log File Data: " << logFileData << std::endl;
}

void backendMessage::LogEntryRspMsg::deserialize(char*& buffer) {
    this->logFileSize = deserializeStr(buffer);
    this->logFileData = deserializeStr(buffer);
}

void backendMessage::LogEntryRspMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->logFileSize, buffer);
    serializeStr(this->logFileData, buffer);
}

size_t backendMessage::LogEntryRspMsg::getSerializedSize() const {
    return sizeof(uint32_t) + logFileSize.length() + sizeof(uint32_t) + logFileData.length();
}

void backendMessage::DataFileReqMsg::printMsg() const {
    std::cout << "Worker ID: " << workerId << std::endl;
}

void backendMessage::DataFileReqMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->workerId, buffer);
}

void backendMessage::DataFileReqMsg::deserialize(char*& buffer) {
    this->workerId = deserializeStr(buffer);
}

size_t backendMessage::DataFileReqMsg::getSerializedSize() const {
    return sizeof(uint32_t) + workerId.length();
}

void backendMessage::DataFileRspMsg::printMsg() const {
    std::cout << "dirName: " << dirName << std::endl;
    std::cout << "data: " << data << std::endl;
}

void backendMessage::DataFileRspMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->dirName, buffer);
    serializeStr(this->data, buffer);
}

void backendMessage::DataFileRspMsg::deserialize(char*& buffer) {
    this->dirName = deserializeStr(buffer);
    this->data = deserializeStr(buffer);
}

size_t backendMessage::DataFileRspMsg::getSerializedSize() const {
    return sizeof(uint32_t) + dirName.length() + sizeof(uint32_t) + data.length();
}

void backendMessage::RecoveryDoneMsg::printMsg() const {
    std::cout << "Recovery Done for worker: " << workerId << std::endl;
}

void backendMessage::RecoveryDoneMsg::serialize(std::vector<char>& buffer) const {
    serializeStr(this->workerId, buffer);
}

void backendMessage::RecoveryDoneMsg::deserialize(char*& buffer) {
    this->workerId = deserializeStr(buffer);
}

size_t backendMessage::RecoveryDoneMsg::getSerializedSize() const {
    return sizeof(uint32_t) + workerId.length();
}

void backendMessage::GetInfoReqMsg::printMsg() const {
    std::cout << "Get Info Request " << std::endl;
}

void backendMessage::GetInfoReqMsg::serialize(std::vector<char>& buffer) const {
    // nothing to serialize
}

void backendMessage::GetInfoReqMsg::deserialize(char*& buffer) {
    // nothing to deserialize
}

size_t backendMessage::GetInfoReqMsg::getSerializedSize() const {
    return 0;
}

void backendMessage::GetInfoRspMsg::printMsg() const {
    for (auto&it : serverInfo) {
        std::cout << "Server Ip: " << it.first << " Status: " << it.second << std::endl;
    }
}

void backendMessage::GetInfoRspMsg::serialize(std::vector<char>& buffer) const {
    uint32_t numServers = htonl(static_cast<uint32_t> (serverInfo.size()));
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&numServers), 
                reinterpret_cast<char*>(&numServers) + sizeof(uint32_t));
    for (auto& it : serverInfo) {
        serializeStr(it.first, buffer);
        serializeStr(it.second, buffer);
    }
}

void backendMessage::GetInfoRspMsg::deserialize(char*& buffer) {
    uint32_t numServers = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    buffer += sizeof(uint32_t);
    for (uint32_t i = 0; i < numServers; i++) {
        std::string ip = deserializeStr(buffer);
        std::string status = deserializeStr(buffer);
        serverInfo[ip] = status;
    }
}

size_t backendMessage::GetInfoRspMsg::getSerializedSize() const {
    size_t size = sizeof(uint32_t);
    for (auto& it : serverInfo) {
        size += sizeof(uint32_t) + it.first.length() + sizeof(uint32_t) + it.second.length();
    }
    return size;
}

void backendMessage::printMsg() const {
    std::cout << "Message Type: " << backendMsgTypeStr.at(msgType) << std::endl;
    std::cout << "Message ID: " << msgId << std::endl;
    switch (msgType)
    {
    case Req:
        std::cout << "Request Type: " << reqTypeToStr(msg.reqMsg.reqType) << std::endl;
        msg.reqMsg.printMsg();
        break;
    case Rsp:
        std::cout << "Response Status: " << rspTypeToStr(msg.rspMsg.status) << std::endl;
        msg.rspMsg.printMsg();
        break;
    case Redir:
        msg.redirMsg.printMsg();
        break;
    case Notify:
        std::cout << "Request Type: " << reqTypeToStr(msg.notifyMsg.reqType) << std::endl;
        msg.notifyMsg.printMsg();
        break;
    case Ack:
        msg.ackMsg.printMsg();
        std::cout << "Status: " << rspTypeToStr(msg.ackMsg.status) << std::endl;
        break;
    case CP:
        msg.cpMsg.printMsg();
        break;
    case CPAck:
        std::cout << "Status: " << rspTypeToStr(msg.cpAckMsg.status) << std::endl;
        break;
    case Assign:
        msg.assignMsg.printMsg();
        break;
    case Shutdown:
        msg.shutdownMsg.printMsg();
        break;
    case Restart:
        msg.restartMsg.printMsg();
        break;
    case Ping:
        msg.pingMsg.printMsg();
        break;
    case Append:
        msg.appendMsg.printMsg();
        break;
    case LogFileReq:
        msg.logFileReqMsg.printMsg();
        break;
    case LogFileRsp:
        msg.logFileRspMsg.printMsg();
        break;
    case LogEntryReq:
        msg.logEntryReqMsg.printMsg();
        break;
    case LogEntryRsp:
        msg.logEntryRspMsg.printMsg();
        break;
    case DataFileReq:
        msg.dataFileReqMsg.printMsg();
        break;
    case DataFileRsp:
        msg.dataFileRspMsg.printMsg();
        break;
    case RecoveryDone:
        msg.recoveryDoneMsg.printMsg();
        break;
    case GetInfoReq:
        msg.getInfoReqMsg.printMsg();
        break;
    case GetInfoRsp:
        msg.getInfoRspMsg.printMsg();
        break;
    case UNKNOWN:
        std::cout << "Error: Printing Unknown Message Type" << std::endl;
        break;
    default:
        std::cout << "Error: Printing Unkown Message Type" << std::endl;
        break;
    }
    std::cout << "Is End: " << isEnd << std::endl;
}

void backendMessage::serialize(std::vector<char>& buffer) const {
    uint32_t msgSize = htonl(getSerializedSize());
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&msgSize), 
                reinterpret_cast<char*>(&msgSize) + sizeof(msgSize));
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&msgType), 
                reinterpret_cast<const char*>(&msgType) + sizeof(msgType));
    serializeStr(msgId, buffer);
    uint16_t currEnd = htons(this->isEnd);
    buffer.insert(buffer.end(), reinterpret_cast<char*>(&currEnd), 
                reinterpret_cast<char*>(&currEnd) + sizeof(uint16_t));
    switch (msgType)
    {
    case Req:
        msg.reqMsg.serialize(buffer);
        break;
    case Rsp:
        msg.rspMsg.serialize(buffer);
        break;
    case Redir:
        msg.redirMsg.serialize(buffer);
        break;
    case Notify:
        msg.notifyMsg.serialize(buffer);
        break;
    case Ack:
        msg.ackMsg.serialize(buffer);
        break;
    case CP:
        msg.cpMsg.serialize(buffer);
        break;
    case CPAck:
        msg.cpAckMsg.serialize(buffer);
        break;
    case Assign:
        msg.assignMsg.serialize(buffer);
        break;
    case Shutdown:
        msg.shutdownMsg.serialize(buffer);
        break;
    case Restart:
        msg.restartMsg.serialize(buffer);
        break;
    case Ping:
        msg.pingMsg.serialize(buffer);
        break;
    case Append:
        msg.appendMsg.serialize(buffer);
        break;
    case LogFileReq:
        msg.logFileReqMsg.serialize(buffer);
        break;
    case LogFileRsp:
        msg.logFileRspMsg.serialize(buffer);
        break;
    case LogEntryReq:
        msg.logEntryReqMsg.serialize(buffer);
        break;
    case LogEntryRsp:
        msg.logEntryRspMsg.serialize(buffer);
        break;
    case DataFileReq:
        msg.dataFileReqMsg.serialize(buffer);
        break;
    case DataFileRsp:
        msg.dataFileRspMsg.serialize(buffer);
        break;
    case RecoveryDone:
        msg.recoveryDoneMsg.serialize(buffer);
        break;
    case GetInfoReq:
        msg.getInfoReqMsg.serialize(buffer);
        break;
    case GetInfoRsp:
        msg.getInfoRspMsg.serialize(buffer);
        break;
    default:
        std::cout << "Error: Serializing Unkown Message Type" << std::endl;
        break;
    }
}

bool backendMessage::deserialize(char*& buffer, uint32_t size) {
    uint32_t msgSize = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    if (msgSize > size) {
        return false;
    }
    buffer += sizeof(uint32_t);
    this->msgType = static_cast<messageType> (*reinterpret_cast<char*>(buffer));
    if (backendMsgTypeStr.find(this->msgType) == backendMsgTypeStr.end()) {
        buffer -= sizeof(uint32_t) + sizeof(msgType);
        std::cout << "Error: Deserializing Unkown Message Type" << std::endl;
        return false;
    }
    buffer += sizeof(msgType);
    this->msgId = deserializeStr(buffer);
    this->isEnd = ntohs(*reinterpret_cast<uint16_t*>(buffer));
    buffer += sizeof(uint16_t);
    switch(msgType)
    {
    case Req:
        msg.reqMsg.deserialize(buffer);
        break;
    case Rsp:
        msg.rspMsg.deserialize(buffer);
        break;
    case Redir:
        msg.redirMsg.deserialize(buffer);
        break;
    case Notify:
        msg.notifyMsg.deserialize(buffer);
        break;
    case Ack:
        msg.ackMsg.deserialize(buffer);
        break;
    case CP:
        msg.cpMsg.deserialize(buffer);
        break;
    case CPAck:
        msg.cpAckMsg.deserialize(buffer);
        break;
    case Assign:
        msg.assignMsg.deserialize(buffer);
        break;
    case Shutdown:
        msg.shutdownMsg.deserialize(buffer);
        break;
    case Restart:
        msg.restartMsg.deserialize(buffer);
        break;
    case Ping:
        msg.pingMsg.deserialize(buffer);
        break;
    case Append:
        msg.appendMsg.deserialize(buffer);
        break;
    case LogFileReq:
        msg.logFileReqMsg.deserialize(buffer);
        break;
    case LogFileRsp:
        msg.logFileRspMsg.deserialize(buffer);
        break;
    case LogEntryReq:
        msg.logEntryReqMsg.deserialize(buffer);
        break;
    case LogEntryRsp:
        msg.logEntryRspMsg.deserialize(buffer);
        break;
    case DataFileReq:
        msg.dataFileReqMsg.deserialize(buffer);
        break;
    case DataFileRsp:
        msg.dataFileRspMsg.deserialize(buffer);
        break;
    case RecoveryDone:
        msg.recoveryDoneMsg.deserialize(buffer);
        break;
    case GetInfoReq:
        msg.getInfoReqMsg.deserialize(buffer);
        break;
    case GetInfoRsp:
        msg.getInfoRspMsg.deserialize(buffer);
        break;
    default:
        msgType = UNKNOWN;
        std::cout << "Error: Deserializing Unkown Message Type" << std::endl;
        break;
    }
    buffer -= getSerializedSize();
    return true;
}

size_t backendMessage::getSerializedSize() const {
    size_t size = sizeof(uint32_t) + sizeof(msgType) + sizeof(uint32_t) + msgId.length() + sizeof(uint16_t);
    switch(msgType)
    {
    case Req:
        size += msg.reqMsg.getSerializedSize();
        break;
    case Rsp:
        size += msg.rspMsg.getSerializedSize();
        break;
    case Redir:
        size += msg.redirMsg.getSerializedSize();
        break;
    case Notify:
        size += msg.notifyMsg.getSerializedSize();
        break;
    case Ack:
        size += msg.ackMsg.getSerializedSize();
        break;
    case CP:
        size += msg.cpMsg.getSerializedSize();
        break;
    case CPAck:
        size += msg.cpAckMsg.getSerializedSize();
        break;
    case Assign:
        size += msg.assignMsg.getSerializedSize();
        break;
    case Shutdown:
        size += msg.shutdownMsg.getSerializedSize();
        break;
    case Restart:
        size += msg.restartMsg.getSerializedSize();
        break;
    case Ping:
        size += msg.pingMsg.getSerializedSize();
        break;
    case Append:
        size += msg.appendMsg.getSerializedSize();
        break;
    case LogFileReq:
        size += msg.logFileReqMsg.getSerializedSize();
        break;
    case LogFileRsp:
        size += msg.logFileRspMsg.getSerializedSize();
        break;
    case LogEntryReq:
        size += msg.logEntryReqMsg.getSerializedSize();
        break;
    case LogEntryRsp:
        size += msg.logEntryRspMsg.getSerializedSize();
        break;
    case DataFileReq:
        size += msg.dataFileReqMsg.getSerializedSize();
        break;
    case DataFileRsp:
        size += msg.dataFileRspMsg.getSerializedSize();
        break;
    case RecoveryDone:
        size += msg.recoveryDoneMsg.getSerializedSize();
        break;
    case GetInfoReq:
        size += msg.getInfoReqMsg.getSerializedSize();
        break;
    case GetInfoRsp:
        size += msg.getInfoRspMsg.getSerializedSize();
        break;
    default:
        std::cout << "Error: Getting Serialized Size of Unkown Message Type" << std::endl;
        break;
    }
    return size;
}

void backendMessage::setReqMsg(backendMessage::requestType reqType, std::string tableName, 
                               std::string rowName, std::string colName, 
                               std::string matchVal, std::string newVal) {
    msgType = Req;
    msg.reqMsg.reqType = reqType;
    msg.reqMsg.tableName = tableName;
    msg.reqMsg.rowName = rowName;
    msg.reqMsg.colName = colName;
    msg.reqMsg.matchVal = matchVal;
    msg.reqMsg.newVal = newVal;
}

void backendMessage::setRspMsg(backendMessage::responseType status, std::string content) {
    msgType = Rsp;
    msg.rspMsg.status = status;
    msg.rspMsg.content = content;
}

void backendMessage::setRedirMsg(std::string ipPort) {
    msgType = Redir;
    msg.redirMsg.ipPort = ipPort;
}

void backendMessage::setNotifyMsg(std::string reqId, backendMessage::requestType reqType, 
                                    std::string sourceId,
                                    std::string tableName, std::string rowName, 
                                    std::string colName, std::string newVal) {
    msgType = Notify;
    msg.notifyMsg.reqId = reqId;
    msg.notifyMsg.reqType = reqType;
    msg.notifyMsg.sourceId = sourceId;
    msg.notifyMsg.tableName = tableName;
    msg.notifyMsg.rowName = rowName;
    msg.notifyMsg.colName = colName;
    msg.notifyMsg.newVal = newVal;
}

void backendMessage::setAckMsg(std::string reqId, backendMessage::responseType status) {
    msgType = Ack;
    msg.ackMsg.reqId = reqId;
    msg.ackMsg.status = status;
}

void backendMessage::setCPMsg(uint32_t cpVersion) {
    msgType = CP;
    msg.cpMsg.cpVersion = cpVersion;
}

void backendMessage::setCPAckMsg(backendMessage::responseType status) {
    msgType = CPAck;
    msg.cpAckMsg.status = status;
}

void backendMessage::setAssignMsg(std::string role, std::string primaryIpPort, 
                                  std::vector<std::string> secondaryIpPort,
                                  std::pair<char, char> letterKeyRange,
                                  std::pair<char, char> numKeyRange,
                                  int numSecondariesReady) {
    msgType = Assign;
    msg.assignMsg.role = role;
    msg.assignMsg.primaryIpPort = primaryIpPort;
    msg.assignMsg.secondaryIpPort = secondaryIpPort;
    msg.assignMsg.letterKeyRange = letterKeyRange;
    msg.assignMsg.numKeyRange = numKeyRange;
    msg.assignMsg.numSecondariesReady = numSecondariesReady;
}

void backendMessage::setShutdownMsg() {
    msgType = Shutdown;
}

void backendMessage::setRestartMsg() {
    msgType = Restart;
}

void backendMessage::setPingMsg(char hasKeyRange, std::pair<char, char> letterKeyRange, 
                                std::pair<char, char> numKeyRange) {
    msgType = Ping;
    msg.pingMsg.hasKeyRange = hasKeyRange;
    msg.pingMsg.numKeyRange = numKeyRange;
    msg.pingMsg.letterKeyRange = letterKeyRange;
}

void backendMessage::setAppendMsg(std::string tableName, std::string rowName,
                                std::string colName, std::string appendMsg) {
    msgType = Append;
    msg.appendMsg.tableName = tableName;
    msg.appendMsg.rowName = rowName;
    msg.appendMsg.colName = colName;
    msg.appendMsg.appendMsg = appendMsg;
}

void backendMessage::setLogFileReqMsg(std::string workerId) {
    msgType = LogFileReq;
    msg.logFileReqMsg.workerId = workerId;
}

void backendMessage::setLogFileRspMsg(uint32_t cpVersion) {
    msgType = LogFileRsp;
    msg.logFileRspMsg.cpVersion = cpVersion;
}

void backendMessage::setLogEntryReqMsg(std::string workerId, std::string offset) {
    msgType = LogEntryReq;
    msg.logEntryReqMsg.workerId = workerId;
    msg.logEntryReqMsg.offset = offset;
}

void backendMessage::setLogEntryRspMsg(std::string logFileSize, std::string logFileData) {
    msgType = LogEntryRsp;
    msg.logEntryRspMsg.logFileSize = logFileSize;
    msg.logEntryRspMsg.logFileData = logFileData;
}

void backendMessage::setDataFileReqMsg(std::string workerId) {
    msgType = DataFileReq;
    msg.dataFileReqMsg.workerId = workerId;
}

void backendMessage::setDataFileRspMsg(std::string dirName, std::string data) {
    msgType = DataFileRsp;
    msg.dataFileRspMsg.dirName = dirName;
    msg.dataFileRspMsg.data = data;
}

void backendMessage::setRecoveryDoneMsg(std::string workerId) {
    msgType = RecoveryDone;
    msg.recoveryDoneMsg.workerId = workerId;
}

void backendMessage::setGetInfoReqMsg() {
    msgType = GetInfoReq;
}

void backendMessage::setGetInfoRspMsg(std::map<std::string, std::string> serverInfo) {
    msgType = GetInfoRsp;
    msg.getInfoRspMsg.serverInfo = serverInfo;
}

backendMessage::ReqMsg backendMessage::getReqMsg() const {
    return msg.reqMsg;
}

backendMessage::RspMsg backendMessage::getRspMsg() const {
    return msg.rspMsg;
}

backendMessage::RedirMsg backendMessage::getRedirMsg() const {
    return msg.redirMsg;
}

backendMessage::NotifyMsg backendMessage::getNotifyMsg() const {
    return msg.notifyMsg;
}

backendMessage::AckMsg backendMessage::getAckMsg() const {
    return msg.ackMsg;
}

backendMessage::CPMsg backendMessage::getCPMsg() const {
    return msg.cpMsg;
}

backendMessage::CPAckMsg backendMessage::getCPAckMsg() const {
    return msg.cpAckMsg;
}

backendMessage::AssignMsg backendMessage::getAssignMsg() const {
    return msg.assignMsg;
}

backendMessage::ShutdownMsg backendMessage::getShutdownMsg() const {
    return msg.shutdownMsg;
}

backendMessage::RestartMsg backendMessage::getRestartMsg() const {
    return msg.restartMsg;
}

backendMessage::PingMsg backendMessage::getPingMsg() const {
    return msg.pingMsg;
}

backendMessage::AppendMsg backendMessage::getAppendMsg() const {
    return msg.appendMsg;
}

backendMessage::LogFileReqMsg backendMessage::getLogFileReqMsg() const {
    return msg.logFileReqMsg;
}

backendMessage::LogFileRspMsg backendMessage::getLogFileRspMsg() const {
    return msg.logFileRspMsg;
}

backendMessage::LogEntryReqMsg backendMessage::getLogEntryReqMsg() const {
    return msg.logEntryReqMsg;
}

backendMessage::LogEntryRspMsg backendMessage::getLogEntryRspMsg() const {
    return msg.logEntryRspMsg;
}

backendMessage::DataFileReqMsg backendMessage::getDataFileReqMsg() const {
    return msg.dataFileReqMsg;
}

backendMessage::DataFileRspMsg backendMessage::getDataFileRspMsg() const {
    return msg.dataFileRspMsg;
}

backendMessage::RecoveryDoneMsg backendMessage::getRecoveryDoneMsg() const {
    return msg.recoveryDoneMsg;
}

backendMessage::GetInfoReqMsg backendMessage::getGetInfoReqMsg() const {
    return msg.getInfoReqMsg;
}

backendMessage::GetInfoRspMsg backendMessage::getGetInfoRspMsg() const {
    return msg.getInfoRspMsg;
}

std::string backendMessage::reqTypeToStr(backendMessage::requestType reqType) const {
    switch (reqType)
    {
    case GET:
        return "GET";
    case PUT:
        return "PUT";
    case APPEND:
        return "APPEND";
    case DELETE:
        return "DELETE";
    case CPUT:
        return "CPUT";
    case VERIFY:
        return "VERIFY";
    case GETROW:
        return "GETROW";
    default:
        return "UNKNOWN";
    }
}

std::string backendMessage::rspTypeToStr(backendMessage::responseType rspType) const {
    switch (rspType)
    {
    case OK:
        return "OK";
    case ERR:
        return "ERR";
    case SHUTDOWN:
        return "SHUTDOWN";
    default:
        return "UNKNOWN";
    }
}