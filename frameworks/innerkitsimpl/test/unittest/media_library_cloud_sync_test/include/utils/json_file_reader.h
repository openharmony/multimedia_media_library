/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TDD_JSON_READER_H
#define TDD_JSON_READER_H

#include <charconv>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "mdk_record.h"
#include "mdk_result.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "cloud_meta_data.h"

namespace OHOS::Media::CloudSync {
class JsonFileReader {
private:
    std::string path_;

public:  // constructor & destructor
    JsonFileReader() = default;
    JsonFileReader(const std::string &path) : path_(path) {}

public:
    void ConvertToMDKRecordOperResultMap(std::map<std::string, MDKRecordOperResult> &map)
    {
        GTEST_LOG_(INFO) << "enter ConvertToMDKRecordOperResultMap path:" << path_;
        std::ifstream jsonFile(path_);
        EXPECT_TRUE(jsonFile.is_open()) << "can not open json file:" << path_;
        Json::Value root;
        Json::Reader jsonReader;
        std::string buffer = std::string((std::istreambuf_iterator<char>(jsonFile)), std::istreambuf_iterator<char>());
        jsonReader.parse(buffer, root, false);
        EXPECT_TRUE(root.isObject()) << "parse json error:" << path_;
        EXPECT_TRUE(root.isMember("records") && root["records"].isArray())
            << "parse json error: no records field or records field is not array" << path_;
        GTEST_LOG_(INFO) << "ConvertToMDKRecordOperResultMap path:" << path_
                         << ",record size:" << root["records"].size();
        Json::FastWriter writer;
        for (Json::ArrayIndex i = 0; i < root["records"].size(); i++) {
            MDKRecord record;
            ConvertToMdkRecord(root["records"][i], record);
            MDKError error;
            ConvertToMdkError(root["records"][i], error);
            MDKRecordOperResult result;
            result.SetDKRecord(record);
            result.SetDKError(error);
            Json::Value jsonValue = record.ToJsonValue();
            std::string jsonStr = writer.write(jsonValue);
            GTEST_LOG_(INFO) << "ConvertToMDKRecordOperResultMap Record:" << jsonStr;
            map[record.GetRecordId()] = result;
        }
        jsonFile.close();
        GTEST_LOG_(INFO) << "end ConvertToMDKRecordOperResultMap path:" << path_;
    }

    void ConvertToMDKRecordVector(std::vector<MDKRecord> &records)
    {
        GTEST_LOG_(INFO) << "enter ConvertToMDKRecordVector path:" << path_;
        std::ifstream jsonFile(path_);
        EXPECT_TRUE(jsonFile.is_open()) << "convert records can not open json file:" << path_;
        Json::Value root;
        Json::Reader jsonReader;
        std::string buffer = std::string((std::istreambuf_iterator<char>(jsonFile)), std::istreambuf_iterator<char>());
        jsonReader.parse(buffer, root, false);
        EXPECT_TRUE(root.isObject()) << "convert records parse json error:" << path_;
        EXPECT_TRUE(root.isMember("records") && root["records"].isArray())
            << "convert records parse json error: no records field or records field is not array" << path_;
        GTEST_LOG_(INFO) << "ConvertToMDKRecordVector path:" << path_ << ",record size:" << root["records"].size();
        Json::FastWriter writer;
        for (Json::ArrayIndex i = 0; i < root["records"].size(); i++) {
            MDKRecord record;
            ConvertToMdkRecord(root["records"][i], record);
            Json::Value jsonValue = record.ToJsonValue();
            std::string jsonStr = writer.write(jsonValue);
            GTEST_LOG_(INFO) << "ConvertToMDKRecordVector Record:" << jsonStr;
            records.emplace_back(record);
        }
        jsonFile.close();
        GTEST_LOG_(INFO) << "end ConvertToMDKRecordVector path:" << path_;
    }

    void ConvertToCloudMetaDataVector(std::vector<CloudMetaData> &metaDataList)
    {
        GTEST_LOG_(INFO) << "enter ConvertToCloudMetaDataVector path:" << path_;
        std::ifstream jsonFile(path_);
        EXPECT_TRUE(jsonFile.is_open()) << "convert metaDataList can not open json file:" << path_;
        Json::Value root;
        Json::Reader jsonReader;
        std::string buffer = std::string((std::istreambuf_iterator<char>(jsonFile)), std::istreambuf_iterator<char>());
        jsonReader.parse(buffer, root, false);
        EXPECT_TRUE(root.isObject()) << "convert metaDataList parse json error:" << path_;
        EXPECT_TRUE(root.isMember("records") && root["records"].isArray())
            << "convert metaDataList parse json error: no metadatas field or metadatas field is not array" << path_;
        GTEST_LOG_(INFO) << "ConvertToCloudMetaDataVector path:" << path_ << ",record size:" << root["records"].size();
        for (Json::ArrayIndex i = 0; i < root["records"].size(); i++) {
            CloudMetaData metaData;
            ConvertToCloudMetaData(root["records"][i], metaData);
            GTEST_LOG_(INFO) << "ConvertToCloudMetaDataVector metaData:" << metaData.ToString();
            metaDataList.emplace_back(metaData);
        }
        jsonFile.close();
        GTEST_LOG_(INFO) << "end ConvertToMDKRecordVector path:" << path_;
    }

private:
    using SetRecordField = void (JsonFileReader::*)(const Json::Value &, MDKRecord &);
    std::map<std::string, SetRecordField> MDKRECORD_FUNCS = {
        {"recordId", &JsonFileReader::SetRecordId},     {"recordType", &JsonFileReader::SetRecordType},
        {"deleted", &JsonFileReader::SetDelete},        {"baseVersion", &JsonFileReader::SetVersion},
        {"isNew", &JsonFileReader::SetNewCreate},       {"createdTime", &JsonFileReader::SetCreateTime},
        {"editedTime", &JsonFileReader::SetEditedTime}, {"baseCursor", &JsonFileReader::SetBaseCursor},
        {"ownerId", &JsonFileReader::SetOwnerId},       {"isShared", &JsonFileReader::SetShared},
    };

private:
    void ConvertToMdkRecord(const Json::Value &node, MDKRecord &record)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "members size is empty";
            return;
        }
        std::map<std::string, MDKRecordField> data;
        for (auto &member : members) {
            if (member == "createInfo") {
                SetRecordCreateInfo(node[member], record);
                continue;
            }
            if (member == "modifiedInfo") {
                SetRecordModifiedInfo(node[member], record);
                continue;
            }
            if (member == "relations") {
                SetRecordRelations(node[member], record);
                continue;
            }
            if (member == "albumIds") {
                SetRecordAlbumIds(node[member], data);
                continue;
            }
            auto it = MDKRECORD_FUNCS.find(member);
            if (it != MDKRECORD_FUNCS.end()) {
                (this->*(it->second))(node[member], record);
                continue;
            }
            if (node[member].isArray()) {
                std::vector<MDKRecordField> fields;
                ParseArrayFields(node[member], fields);
                data[member] = MDKRecordField(fields);
            } else if (node[member].isObject()) {
                std::map<std::string, MDKRecordField> fields;
                ParseObjectFields(node[member], fields);
                data[member] = MDKRecordField(fields);
            } else {
                InsertField(node, member, data);
            }
        }
        record.SetRecordData(data);
    }

    void ConvertToMdkError(const Json::Value &node, MDKError &error)
    {
        if (!node.isMember("error")) {
            return;
        }
        Json::Value errValue = node["error"];
        if (errValue.isMember("isLocalError") && errValue["isLocalError"].isBool()) {
            error.isLocalError = errValue["isLocalError"].asBool();
        }
        if (errValue.isMember("dkErrorCode") && errValue["dkErrorCode"].isInt64()) {
            error.dkErrorCode = static_cast<MDKLocalErrorCode>(errValue["dkErrorCode"].asInt64());
        }
        if (errValue.isMember("isServerError") && errValue["isServerError"].isBool()) {
            error.isServerError = errValue["isServerError"].asBool();
        }
        if (errValue.isMember("serverErrorCode") && errValue["serverErrorCode"].isInt64()) {
            error.serverErrorCode = errValue["serverErrorCode"].asInt64();
        }
        if (errValue.isMember("reason") && errValue["reason"].isString()) {
            error.reason = errValue["reason"].asString();
        }
        if (errValue.isMember("retryAfter") && errValue["retryAfter"].isInt64()) {
            error.retryAfter = errValue["retryAfter"].asInt64();
        }
        if (errValue.isMember("errorType") && errValue["errorType"].isInt64()) {
            error.errorType = static_cast<MDKErrorType>(errValue["errorType"].asInt64());
        }
        if (errValue.isMember("errorDetails") && errValue["errorDetails"].isArray()) {
            for (uint32_t i = 0; i < errValue["errorDetails"].size(); i++) {
                MDKErrorDetail detail;
                Json::Value errDetail = errValue["errorDetails"][i];
                ConvertErrorDetail(errDetail, detail);
                error.errorDetails.emplace_back(detail);
            }
        }
    }

    void ConvertErrorDetail(const Json::Value &errDetail, MDKErrorDetail &detail)
    {
        if (errDetail.isMember("domain") && errDetail["domain"].isString()) {
            detail.domain = errDetail["domain"].asString();
        }
        if (errDetail.isMember("reason") && errDetail["reason"].isString()) {
            detail.reason = errDetail["reason"].asString();
        }
        if (errDetail.isMember("errorCode") && errDetail["errorCode"].isString()) {
            detail.errorCode = errDetail["errorCode"].asString();
        }
        if (errDetail.isMember("description") && errDetail["description"].isString()) {
            detail.description = errDetail["description"].asString();
        }
        if (errDetail.isMember("errorPos") && errDetail["errorPos"].isString()) {
            detail.errorPos = errDetail["errorPos"].asString();
        }
        if (errDetail.isMember("errorParam") && errDetail["errorParam"].isString()) {
            detail.errorParam = errDetail["errorParam"].asString();
        }
        if (errDetail.isMember("detailCode") && errDetail["detailCode"].isInt64()) {
            detail.detailCode = errDetail["detailCode"].asInt64();
        }
    }

    int64_t StrToInt64(std::string &str)
    {
        if (str.empty() || str.c_str()[0] == '-' || str.size() > std::to_string(INT64_MAX).size()) {
            return 0;
        }
        std::string aab = "-1";
        int64_t result = 0;
        auto ret = std::from_chars(str.c_str(), str.c_str() + str.size(), result);
        if (ret.ec != std::errc()) {
            result = 0;
        }
        return result;
    }

    void SetRecordCreateInfo(const Json::Value &node, MDKRecord &record)
    {
        MDKRecordsResponse resp;
        if (node["time"].isInt64()) {
            resp.time = node["time"].asInt64();
        }
        if (node["deviceName"].isString()) {
            resp.deviceName = node["deviceName"].asString();
        }
        if (node["appId"].isString()) {
            resp.appId = node["appId"].asString();
        }
        record.SetCreateInfo(resp);
    }

    void SetRecordModifiedInfo(const Json::Value &node, MDKRecord &record)
    {
        MDKRecordsResponse resp;
        if (node["time"].isInt64()) {
            resp.time = node["time"].asInt64();
        }
        if (node["deviceName"].isString()) {
            resp.deviceName = node["deviceName"].asString();
        }
        if (node["appId"].isString()) {
            resp.appId = node["appId"].asString();
        }
        record.SetModifiedInfo(resp);
    }

    void SetRecordRelations(const Json::Value &node, MDKRecord &record)
    {
        if (!node.isArray()) {
            GTEST_LOG_(INFO) << "SetRecordRelations is not array";
            return;
        }
        std::vector<MDKRelation> relations;
        for (uint32_t i = 0; i < node.size(); ++i) {
            MDKRelation relation;
            if (node[i]["relationName"].isString()) {
                relation.relationName = node[i]["relationName"].asString();
            }
            if (node[i]["recordType"].isString()) {
                relation.recordType = node[i]["recordType"].asString();
            }
            if (node[i]["recordId"].isString()) {
                relation.recordId = node[i]["recordId"].asString();
            }
            relations.emplace_back(relation);
        }
        record.SetRecordRelations(relations);
    }

    void SetRecordAlbumIds(const Json::Value &node, std::map<std::string, MDKRecordField> &data)
    {
        if (!node.isArray()) {
            GTEST_LOG_(INFO) << "SetRecordAlbumIds is not array";
            return;
        }

        std::vector<MDKRecordField> albumIdList;
        for (uint32_t i = 0; i < node.size(); ++i) {
            MDKReference ref;
            if (node[i]["recordId"].isString()) {
                ref.recordId = node[i]["recordId"].asString();
            }
            if (node[i]["recordType"].isString()) {
                ref.recordType = node[i]["recordType"].asString();
            }
            MDKRecordField ablumsId(ref);
            albumIdList.emplace_back(ablumsId);
        }
        data["albumIds"] = MDKRecordField(albumIdList);
    }

    void InsertField(const Json::Value &node, std::string &member, std::map<std::string, MDKRecordField> &fields)
    {
        if (node[member].isInt64()) {
            fields[member] = MDKRecordField(node[member].asInt64());
        } else if (node[member].isBool()) {
            fields[member] = MDKRecordField(node[member].asBool());
        } else if (node[member].isDouble()) {
            fields[member] = MDKRecordField(node[member].asDouble());
        } else if (node[member].isArray()) {
            std::vector<MDKRecordField> arrayFields;
            ParseArrayFields(node[member], arrayFields);
            fields[member] = MDKRecordField(arrayFields);
        } else if (node[member].isObject()) {
            std::map<std::string, MDKRecordField> objFields;
            ParseObjectFields(node[member], objFields);
            fields[member] = MDKRecordField(objFields);
        } else if (node[member].isString()) {
            fields[member] = MDKRecordField(node[member].asString());
        } else {
            GTEST_LOG_(ERROR) << "InsertField error type is:" << node[member].type();
        }
    }

    void ParseObjectFields(const Json::Value &node, std::map<std::string, MDKRecordField> &fields)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "ParseObjectFields member size is empty";
            return;
        }
        for (auto &member : members) {
            InsertField(node, member, fields);
        }
    }

    void ParseArrayFields(const Json::Value &node, std::vector<MDKRecordField> &fields)
    {
        for (uint32_t i = 0; i < node.size(); i++) {
            std::map<std::string, MDKRecordField> nodeFields;
            ParseObjectFields(node[i], nodeFields);
            fields.push_back(MDKRecordField(nodeFields));
        }
    }

    void SetRecordId(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isString()) {
            return;
        }
        record.SetRecordId(data.asString());
    }

    void SetRecordType(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isString()) {
            return;
        }
        record.SetRecordType(data.asString());
    }

    void SetDelete(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isBool()) {
            return;
        }
        record.SetDelete(data.asBool());
    }

    void SetVersion(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isInt64()) {
            return;
        }
        record.SetVersion(data.asInt64());
    }

    void SetNewCreate(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isBool()) {
            return;
        }
        record.SetNewCreate(data.asBool());
    }

    void SetShared(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isBool()) {
            return;
        }
        record.SetShared(data.asBool());
    }

    void SetCreateTime(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isInt64()) {
            return;
        }
        record.SetCreateTime(data.asInt64());
    }

    void SetEditedTime(const Json::Value &data, MDKRecord &record)
    {
        int64_t editedTime = 0;
        if (data.isInt64()) {
            record.SetEditedTime(data.asInt64());
            return;
        }
        if (data.isString()) {
            std::string strEditedTime = data.asString();
            editedTime = StrToInt64(strEditedTime);
            record.SetEditedTime(editedTime);
            return;
        }
    }

    void SetBaseCursor(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isString()) {
            return;
        }
        record.SetBaseCursor(data.asString());
    }

    void SetOwnerId(const Json::Value &data, MDKRecord &record)
    {
        if (!data.isString()) {
            return;
        }
        record.SetOwnerId(data.asString());
    }

    void SetRecordRespTime(const Json::Value &data, MDKRecordsResponse &resp)
    {
        if (!data.isInt64()) {
            return;
        }
        resp.time = data.asInt64();
    }

    void SetRecordRespDeviceName(const Json::Value &data, MDKRecordsResponse &resp)
    {
        if (!data.isString()) {
            return;
        }
        resp.deviceName = data.asString();
    }

    void SetRecordRespAppId(const Json::Value &data, MDKRecordsResponse &resp)
    {
        if (!data.isString()) {
            return;
        }
        resp.appId = data.asString();
    }

    void SetRecordRelationName(const Json::Value &data, MDKRelation &resp)
    {
        if (!data.isString()) {
            return;
        }
        resp.relationName = data.asString();
    }

    void SetRecordRelationType(const Json::Value &data, MDKRelation &resp)
    {
        if (!data.isString()) {
            return;
        }
        resp.recordType = data.asString();
    }

    void SetRecordRelationId(const Json::Value &data, MDKRelation &resp)
    {
        if (!data.isString()) {
            return;
        }
        resp.recordId = data.asString();
    }

private:
    using SetCloudMetaDataField = void (JsonFileReader::*)(const Json::Value &, CloudMetaData &);
    std::map<std::string, SetCloudMetaDataField> CLOUDMETADATA_FUNCS = {
        {"recordId", &JsonFileReader::SetMetaDataCloudId},
        {"cloudId", &JsonFileReader::SetMetaDataCloudId},
        {"size", &JsonFileReader::SetMetaDataSize},
        {"fileName", &JsonFileReader::SetMetaDataFileName},
        {"path", &JsonFileReader::SetMetaDataPath},
        {"modifiedTime", &JsonFileReader::SetMetaDataModifiedTime},
        {"fileType", &JsonFileReader::SetMetaDataFileType},  //type
        {"type", &JsonFileReader::SetMetaDataType},          //type
        {"originalCloudId", &JsonFileReader::SetMetaDataOriginalCloudId},
    };

    using SetPropertiesMetaData = void (JsonFileReader::*)(const Json::Value &, CloudMetaData &);
    std::map<std::string, SetPropertiesMetaData> PROPERTIES_CLOUDMETA_FUNCS = {
        {"sourcePath", &JsonFileReader::SetMetaDataPath},  //path
    };

    using SetAttributesMetaData = void (JsonFileReader::*)(const Json::Value &, CloudMetaData &);
    std::map<std::string, SetAttributesMetaData> ATTRIBUTES_CLOUDMETA_FUNCS = {
        {"editedTime_ms", &JsonFileReader::SetMetaDataModifiedTime},  // modifiedTime
        {"thumb_size", &JsonFileReader::SetAttchmentThumbSize},
        {"lcd_size", &JsonFileReader::SetAttchmentLcdSize},
    };

    using SetAttachmentField = void (JsonFileReader::*)(const Json::Value &, CloudFileData &);
    std::map<std::string, SetAttachmentField> ATTCHMENT_FUNCS = {
        {"assetName", &JsonFileReader::SetAttchmentFileName}, {"subPath", &JsonFileReader::SetAttchmentFilePath},
    };

private:
    void ConvertToCloudMetaData(const Json::Value &node, CloudMetaData &metaData)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "members size is empty";
            return;
        }
        for (auto &member : members) {
            auto it = CLOUDMETADATA_FUNCS.find(member);
            if (it != CLOUDMETADATA_FUNCS.end()) {
                (this->*(it->second))(node[member], metaData);
                continue;
            }
            if (member == "attributes" && node[member].isObject()) {
                ParseObjectAttributes(node[member], metaData);
            } else if (member == "properties" && node[member].isObject()) {
                ParseObjectProperties(node[member], metaData);
            } else if (member == "attachment" && node[member].isArray()) {
                ParseMetaDataAttachment(node[member], metaData.attachment);
            } else {
                MEDIA_ERR_LOG("invalid member");
            }
        }
    }

    void SetMetaDataCloudId(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isString()) {
            return;
        }
        metaData.cloudId = data.asString();
    }

    void SetMetaDataSize(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        metaData.size = data.asInt64();
    }

    void SetMetaDataFileName(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isString()) {
            return;
        }
        metaData.fileName = data.asString();
    }

    void SetMetaDataPath(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isString()) {
            return;
        }
        metaData.path = data.asString();
    }

    void SetMetaDataType(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        int64_t type = data.asInt64();
        metaData.type = type;
    }

    void SetMetaDataFileType(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        int64_t type = data.asInt64();
        metaData.type = (type == 4) ? 2 : 1;  //根据fileType生成mediaType 4->2 vedio, other->1 image
    }

    void SetMetaDataModifiedTime(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        metaData.modifiedTime = data.asInt64();
    }

    void SetAttchmentThumbSize(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        metaData.attachment["thumbnail"].size = data.asInt64();
    }

    void SetAttchmentLcdSize(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isInt64()) {
            return;
        }
        metaData.attachment["lcd"].size = data.asInt64();
    }

    void SetMetaDataOriginalCloudId(const Json::Value &data, CloudMetaData &metaData)
    {
        if (!data.isString()) {
            return;
        }
        metaData.originalCloudId = data.asString();
    }

    void ParseObjectProperties(const Json::Value &node, CloudMetaData &metaData)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "ParseObjectAttributes member size is empty";
            return;
        }
        for (auto &member : members) {
            auto it = PROPERTIES_CLOUDMETA_FUNCS.find(member);
            if (it != PROPERTIES_CLOUDMETA_FUNCS.end()) {
                (this->*(it->second))(node[member], metaData);
                continue;
            }
        }
    }

    void ParseObjectAttributes(const Json::Value &node, CloudMetaData &metaData)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "ParseObjectAttributes member size is empty";
            return;
        }
        for (auto &member : members) {
            auto it = ATTRIBUTES_CLOUDMETA_FUNCS.find(member);
            if (it != ATTRIBUTES_CLOUDMETA_FUNCS.end()) {
                (this->*(it->second))(node[member], metaData);
                continue;
            }
        }
    }

    void ParseObjectAttachment(const Json::Value &node, CloudFileData &attachment)
    {
        std::vector<std::string> members = node.getMemberNames();
        if (members.size() <= 0) {
            GTEST_LOG_(INFO) << "ParseObjectAttachment member size is empty";
            return;
        }
        for (auto &member : members) {
            auto it = ATTCHMENT_FUNCS.find(member);
            if (it != ATTCHMENT_FUNCS.end()) {
                (this->*(it->second))(node[member], attachment);
                continue;
            }
        }
    }

    void ParseMetaDataAttachment(const Json::Value &node, std::map<std::string, CloudFileData> &attachment)
    {
        for (uint32_t i = 0; i < node.size(); i++) {
            CloudFileData data;
            if (!node[i].isObject()) {
                continue;
            }
            std::string mapKey;
            if (node[i].isMember("lcd")) {
                mapKey = "lcd";
            } else if (node[i].isMember("thumbnail")) {
                mapKey = "thumbnail";
            } else {
                continue;
            }
            Json::Value child = node[i][mapKey];
            std::string key = "fileName";
            if (child.isMember(key) && child[key].isString()) {
                data.fileName = child[key].asString();
            }
            key = "filePath";
            if (child.isMember(key) && child[key].isString()) {
                data.filePath = child[key].asString();
            }
            key = "size";
            if (child.isMember(key) && child[key].isInt64()) {
                data.size = child[key].asInt64();
            }
            attachment[mapKey] = data;
        }
    }

    void SetAttchmentFileName(const Json::Value &data, CloudFileData &assetInfo)
    {
        if (!data.isString()) {
            return;
        }
        assetInfo.fileName = data.asString();
    }

    void SetAttchmentFilePath(const Json::Value &data, CloudFileData &assetInfo)
    {
        if (!data.isString()) {
            return;
        }
        assetInfo.filePath = data.asString();
    }

    void SetAttchmentFileSize(const Json::Value &data, CloudFileData &assetInfo)
    {
        if (!data.isInt64()) {
            return;
        }
        assetInfo.size = data.asInt64();
    }

public:
    std::string ToString()
    {
        std::stringstream ss;
        return ss.str();
    }
};
}  // namespace OHOS::Media
#endif  // TDD_JSON_READER_H