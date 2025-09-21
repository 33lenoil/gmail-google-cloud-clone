/*
 * This is a class for communication protocol between backend servers frontend and backend servers, and smtp server and backend servers.
 * It contains the message types and the structures for each message type, getters and setters for each message type,
 * as well as functions to serialize and deserialize the messages.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>

#ifndef backendMessage_H
#define backendMessage_H
#define CONTENTLENGTH 9000

static void serializeStr(std::string str, std::vector<char>& buf);
static std::string deserializeStr(char*& buffer);

class backendMessage {
    public:
        backendMessage();
        virtual ~backendMessage();

        enum messageType {
            UNKNOWN = 0, // unknown message type
            Req = 1, // for frontend request
            Rsp = 2, // for backend response
            Redir = 3, // coordinator tells frontend which backend to request from
            Notify = 4, // for notifying other replicas about write operation
            Ack = 5, // send ack to primary after finishing write to replica
            CP = 6, // coordinator asks replicas to checkpoint
            CPAck = 7, // replica sends ack to coordinator after checkpointing
            Assign = 8, // coordinator assigns role to replica
            Shutdown = 9, // shutdown message to backend servers from adminConsole
            Ping = 10, // ping message to coordinator for liveness check
            Append = 11, // if data doesn't fit in one packet, use this for additional data
            LogFileReq = 12, // request the log file version from primary during recovery
            LogFileRsp = 13, // response to log file version request
            LogEntryReq = 14, // request the newly added log entries from primary during recovery
            LogEntryRsp = 15, // response to log entry request
            DataFileReq = 16, // request the data file from primary during recovery
            DataFileRsp = 17, // response to data file request
            RecoveryDone = 18, // notify coordinator that recovery is done
            Restart = 19, // restart message to backend servers from adminConsole
            GetInfoReq = 20, // request the info for servers in the system
            GetInfoRsp = 21, // response with info on servers in the system
        };

        enum requestType {
            GET = 1, // get a value from a table
            PUT = 2, // put a value in a table
            CPUT = 3, // conditional put a value in a table 
            DELETE = 4, // delete a value from a table
            APPEND = 5, // append a value to a cell
            VERIFY = 6, // verify user credentials
            GETROW = 7, // get all colnames for a row from a table
        };

        enum responseType {
            OK = 1, // operation successful
            ERR = 2, // operation failed
            SHUTDOWN = 3, // shutdown message
        };

        struct ReqMsg {
            backendMessage::requestType reqType;
            std::string tableName;
            std::string rowName;
            std::string colName;
            std::string matchVal;
            std::string newVal;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct RspMsg {
            backendMessage::responseType status;
            std::string content;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct RedirMsg {
            std::string ipPort;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct NotifyMsg {
            std::string reqId;
            backendMessage::requestType reqType;
            std::string sourceId;
            std::string tableName;
            std::string rowName;
            std::string colName;
            std::string newVal;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct AckMsg {
            std::string reqId;
            backendMessage::responseType status;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct CPMsg {
            uint32_t cpVersion;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct CPAckMsg {
            backendMessage::responseType status;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct AssignMsg {
            std::string role;
            std::string primaryIpPort;
            std::vector<std::string> secondaryIpPort;
            std::pair<char, char> letterKeyRange;
            std::pair<char, char> numKeyRange;
            int numSecondariesReady;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        }; 

        struct ShutdownMsg {
            std::string shutdownMsg = "shutdown";
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct RestartMsg {
            std::string restartMsg = "restart";
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct PingMsg {
            char hasKeyRange = 'F';
            std::pair<char, char> letterKeyRange;
            std::pair<char, char> numKeyRange;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct AppendMsg {
            std::string tableName;
            std::string rowName;
            std::string colName;
            std::string appendMsg;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct LogFileReqMsg {
            std::string workerId;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct LogFileRspMsg {
            uint32_t cpVersion;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct LogEntryReqMsg {
            std::string workerId;
            std::string offset;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct LogEntryRspMsg {
            std::string logFileSize;
            std::string logFileData;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct DataFileReqMsg {
            std::string workerId;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct DataFileRspMsg {
            std::string dirName;
            std::string data;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct RecoveryDoneMsg {
            std::string workerId;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct GetInfoReqMsg {
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct GetInfoRspMsg {
            // {ipPort : status}
            std::map<std::string, std::string> serverInfo;
            uint32_t cpVersion;
            void printMsg() const;
            void serialize(std::vector<char>& buffer) const;
            void deserialize(char*& buffer);
            size_t getSerializedSize() const;
        };

        struct {
            ReqMsg reqMsg;
            RspMsg rspMsg;
            RedirMsg redirMsg;
            NotifyMsg notifyMsg;
            AckMsg ackMsg;
            CPMsg cpMsg;
            CPAckMsg cpAckMsg;
            AssignMsg assignMsg;
            ShutdownMsg shutdownMsg;
            RestartMsg restartMsg;
            PingMsg pingMsg;
            AppendMsg appendMsg;
            LogFileReqMsg logFileReqMsg;
            LogFileRspMsg logFileRspMsg;
            LogEntryReqMsg logEntryReqMsg;
            LogEntryRspMsg logEntryRspMsg;
            DataFileReqMsg dataFileReqMsg;
            DataFileRspMsg dataFileRspMsg;
            RecoveryDoneMsg recoveryDoneMsg;
            GetInfoReqMsg getInfoReqMsg;
            GetInfoRspMsg getInfoRspMsg;
        } msg;

        messageType msgType = UNKNOWN;
        std::string msgId = "";
        uint16_t isEnd; // 1 if this is the last packet, 0 otherwise
        backendMessage(backendMessage::messageType msgType, std::string msgId, uint16_t isEnd);
        void printMsg() const;
        void serialize(std::vector<char>& buffer) const;
        bool deserialize(char*& buffer, uint32_t size);
        size_t getSerializedSize() const;

        // functions to set each message type
        void setReqMsg(backendMessage::requestType reqType, std::string tableName, 
                       std::string rowName, std::string colName, 
                       std::string matchVal, std::string newVal);
        void setRspMsg(backendMessage::responseType status, std::string content);
        void setRedirMsg(std::string ipPort);
        void setNotifyMsg(std::string reqId, backendMessage::requestType reqType, std::string sourceId, 
                          std::string tableName, std::string rowName, 
                          std::string colName, std::string newVal);
        void setAckMsg(std::string reqId, backendMessage::responseType status);
        void setCPMsg(uint32_t cpVersion);
        void setCPAckMsg(backendMessage::responseType status);
        void setAssignMsg(std::string role, std::string primaryIpPort, 
                         std::vector<std::string> secondaryIpPort,
                         std::pair<char, char> letterKeyRange,
                         std::pair<char, char> numKeyRange,
                         int numSecondariesReady);
        void setShutdownMsg();
        void setRestartMsg();
        void setPingMsg(char hasKeyRange, std::pair<char, char> letterKeyRange,
                        std::pair<char, char> numKeyRange);
        void setAppendMsg(std::string tableName, std::string rowName,
                        std::string colName, std::string appendMsg);
        void setLogFileReqMsg(std::string workerId);
        void setLogFileRspMsg(uint32_t cpVersion);
        void setLogEntryReqMsg(std::string workerId, std::string offset);
        void setLogEntryRspMsg(std::string logFileSize, std::string logFileData);
        void setDataFileReqMsg(std::string workerId);
        void setDataFileRspMsg(std::string dirName, std::string data);
        void setRecoveryDoneMsg(std::string workerId);
        void setGetInfoReqMsg();
        void setGetInfoRspMsg(std::map<std::string, std::string> serverInfo);

        // functions to get each message type
        ReqMsg getReqMsg() const;
        RspMsg getRspMsg() const;
        RedirMsg getRedirMsg() const;
        NotifyMsg getNotifyMsg() const;
        AckMsg getAckMsg() const;
        CPMsg getCPMsg() const;
        CPAckMsg getCPAckMsg() const;
        AssignMsg getAssignMsg() const;
        ShutdownMsg getShutdownMsg() const;
        RestartMsg getRestartMsg() const;
        PingMsg getPingMsg() const;
        AppendMsg getAppendMsg() const;
        LogFileReqMsg getLogFileReqMsg() const;
        LogFileRspMsg getLogFileRspMsg() const;
        LogEntryReqMsg getLogEntryReqMsg() const;
        LogEntryRspMsg getLogEntryRspMsg() const;
        DataFileReqMsg getDataFileReqMsg() const;
        DataFileRspMsg getDataFileRspMsg() const;
        RecoveryDoneMsg getRecoveryDoneMsg() const;
        GetInfoReqMsg getGetInfoReqMsg() const;
        GetInfoRspMsg getGetInfoRspMsg() const;

        std::string reqTypeToStr(backendMessage::requestType reqType) const;
        std::string rspTypeToStr(backendMessage::responseType rspType) const;
};

#endif