/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "Media_Client"

#include "mdk_record_field.h"
#include "mdk_database.h"
#include "json_helper.h"

namespace OHOS::Media::CloudSync {
// LCOV_EXCL_START
MDKRecordField::MDKRecordField() : type_(MDKRecordFieldType::FIELD_TYPE_NULL)
{}
MDKRecordField::~MDKRecordField()
{}
MDKRecordField::MDKRecordField(MDKFieldValue fieldValue) noexcept : value_(std::move(fieldValue))
{
    type_ = MDKRecordFieldType(value_.index());
}
MDKRecordField::MDKRecordField(const MDKRecordField &recordField)
{
    if (this == &recordField) {
        return;
    }
    type_ = recordField.type_;
    value_ = recordField.value_;
}

MDKRecordField::MDKRecordField(int val) : type_(MDKRecordFieldType::FIELD_TYPE_INT)
{
    value_ = static_cast<int64_t>(val);
}
MDKRecordField::MDKRecordField(int64_t val) : type_(MDKRecordFieldType::FIELD_TYPE_INT)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(double val) : type_(MDKRecordFieldType::FIELD_TYPE_DOUBLE)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(bool val) : type_(MDKRecordFieldType::FIELD_TYPE_BOOL)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(const char *val) : type_(MDKRecordFieldType::FIELD_TYPE_STRING)
{
    value_ = std::string(val);
}
MDKRecordField::MDKRecordField(const std::string &val) : type_(MDKRecordFieldType::FIELD_TYPE_STRING)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(const std::vector<uint8_t> &val) : type_(MDKRecordFieldType::FIELD_TYPE_BLOB)
{
    std::vector<uint8_t> blob = val;
    value_ = blob;
}
MDKRecordField::MDKRecordField(std::map<std::string, MDKRecordField> &val) : type_(MDKRecordFieldType::FIELD_TYPE_MAP)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(std::vector<MDKRecordField> &val) : type_(MDKRecordFieldType::FIELD_TYPE_LIST)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(MDKAsset &val) : type_(MDKRecordFieldType::FIELD_TYPE_ASSET)
{
    value_ = val;
}
MDKRecordField::MDKRecordField(MDKReference &val) : type_(MDKRecordFieldType::FIELD_TYPE_REFERENCE)
{
    value_ = val;
}
MDKRecordField &MDKRecordField::operator=(const MDKRecordField &recordField)
{
    if (this == &recordField) {
        return *this;
    }
    type_ = recordField.type_;
    value_ = recordField.value_;
    return *this;
}

MDKRecordFieldType MDKRecordField::GetType() const
{
    return type_;
}
MDKFieldValue MDKRecordField::GetFieldValue() const
{
    return value_;
}
MDKLocalErrorCode MDKRecordField::GetInt(int &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_INT) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    int64_t v = std::get<int64_t>(value_);
    val = static_cast<int>(v);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetLong(int64_t &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_INT) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    val = std::get<int64_t>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetDouble(double &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_DOUBLE) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    val = std::get<double>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetBool(bool &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_BOOL) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    val = std::get<bool>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetString(std::string &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_STRING) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    val = std::get<std::string>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetBlob(std::vector<uint8_t> &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_BLOB) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }

    val = std::get<std::vector<uint8_t>>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetRecordList(std::vector<MDKRecordField> &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_LIST) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }
    val = std::get<std::vector<MDKRecordField>>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetRecordMap(std::map<std::string, MDKRecordField> &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_MAP) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }
    val = std::get<std::map<std::string, MDKRecordField>>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetAsset(MDKAsset &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_ASSET) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }
    val = std::get<MDKAsset>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}
MDKLocalErrorCode MDKRecordField::GetReference(MDKReference &val) const
{
    if (type_ != MDKRecordFieldType::FIELD_TYPE_REFERENCE) {
        return MDKLocalErrorCode::DATA_TYPE_ERROR;
    }
    val = std::get<MDKReference>(value_);
    return MDKLocalErrorCode::NO_ERROR;
}

Json::Value MDKRecordField::FieldListToJsonValue()
{
    Json::Value jvData;
    std::vector<MDKRecordField> recordLst;
    GetRecordList(recordLst);
    for (auto &record : recordLst) {
        jvData.append(record.ToJsonValue());
    }
    return jvData;
}

Json::Value MDKRecordField::FieldMapToJsonValue()
{
    Json::Value jvData;
    std::map<std::string, MDKRecordField> recordMap;
    GetRecordMap(recordMap);
    for (auto it = recordMap.begin(); it != recordMap.end(); it++) {
        jvData[it->first.c_str()] = it->second.ToJsonValue();
    }
    return jvData;
}
Json::Value MDKRecordField::AssetToJsonValue(const MDKAsset &asset)
{
    Json::Value jvAsset;
    jvAsset["uri"] = asset.uri;
    jvAsset["assetName"] = asset.assetName;
    jvAsset["assetOperType"] = static_cast<int>(asset.operationType);
    jvAsset["sha256"] = asset.hash;
    jvAsset["version"] = asset.version;
    jvAsset["assetId"] = asset.assetId;
    jvAsset["subPath"] = asset.subPath;
    jvAsset["exCheckInfo"] = asset.exCheckInfo;
    jvAsset["size"] = asset.size;
    return jvAsset;
}
Json::Value MDKRecordField::FieldAssetToJsonValue()
{
    MDKAsset asset = std::get<MDKAsset>(value_);
    return AssetToJsonValue(asset);
}

Json::Value MDKRecordField::FieldReferenceToJsonValue()
{
    MDKReference ref = std::get<MDKReference>(value_);
    Json::Value jvReference;
    jvReference["recordId"] = ref.recordId;
    jvReference["recordType"] = ref.recordType;
    return jvReference;
}

Json::Value MDKRecordField::ToJsonValue()
{
    Json::Value jvData;
    switch (type_) {
        case MDKRecordFieldType::FIELD_TYPE_NULL: {
            jvData = Json::nullValue;
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_INT: {
            jvData = std::get<int64_t>(value_);
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_DOUBLE: {
            jvData = std::get<double>(value_);
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_STRING: {
            jvData = std::get<std::string>(value_);
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_BOOL: {
            jvData = std::get<bool>(value_);
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_BLOB: {
            // do not support blob to json in MDKRecordField
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_LIST: {
            jvData = FieldListToJsonValue();
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_MAP: {
            jvData = FieldMapToJsonValue();
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_ASSET: {
            jvData = FieldAssetToJsonValue();
            break;
        }
        case MDKRecordFieldType::FIELD_TYPE_REFERENCE: {
            jvData = FieldReferenceToJsonValue();
            break;
        }
        default:
            break;
    }
    return jvData;
}

bool MDKRecordField::ParseIntFromJson(const Json::Value &jvData)
{
    auto ret = jvData.isInt64() ? true : false;
    if (ret) {
        value_ = jvData.asInt64();
    }
    return ret;
}

bool MDKRecordField::ParseDoubleFromJson(const Json::Value &jvData)
{
    auto ret = jvData.isDouble() ? true : false;
    if (ret) {
        value_ = jvData.asDouble();
    }
    return ret;
}

bool MDKRecordField::ParseStringFromJson(const Json::Value &jvData)
{
    auto ret = jvData.isString() ? true : false;
    if (ret) {
        value_ = jvData.asString();
    }
    return ret;
}

bool MDKRecordField::ParseBoolFromJson(const Json::Value &jvData)
{
    auto ret = jvData.isBool() ? true : false;
    if (ret) {
        value_ = jvData.asBool();
    }
    return ret;
}

bool MDKRecordField::ParseBlobFromJson(const Json::Value &jvData)
{
    return false;
}

bool MDKRecordField::ParseListFromJson(MDKRecordFieldType listType, const Json::Value &jvData)
{
    bool ret = true;
    if (!jvData.isArray()) {
        return false;
    }
    std::vector<MDKRecordField> lst;
    MDKSchemaField schemaField;
    schemaField.type = listType;
    for (Json::ArrayIndex i = 0; i < jvData.size(); i++) {
        MDKRecordField field;
        if (field.ParseFromJsonValue(schemaField, jvData[i])) {
            lst.push_back(field);
        } else {
            ret = false;
        }
    }
    value_ = lst;
    return ret;
}

bool MDKRecordField::ParseMapFromJson(const Json::Value &jvData)
{
    bool ret = true;
    if (!jvData.isObject()) {
        return false;
    }
    std::map<std::string, MDKRecordField> fieldMap;
    auto mem = jvData.getMemberNames();
    for (auto &key : mem) {
        MDKRecordField field;
        const Json::Value &jvValue = jvData[key];
        if (jvValue.isInt64()) {
            field.type_ = MDKRecordFieldType::FIELD_TYPE_INT;
            field.value_ = jvValue.asInt64();
        } else if (jvValue.isDouble()) {
            field.type_ = MDKRecordFieldType::FIELD_TYPE_DOUBLE;
            field.value_ = jvValue.asDouble();
        } else if (jvValue.isString()) {
            field.type_ = MDKRecordFieldType::FIELD_TYPE_STRING;
            field.value_ = jvValue.asString();
        } else if (jvValue.isBool()) {
            field.type_ = MDKRecordFieldType::FIELD_TYPE_BOOL;
            field.value_ = jvValue.asBool();
        } else {
            ret = false;
            continue;
        }
        fieldMap[key] = field;
    }
    value_ = fieldMap;
    return ret;
}

bool MDKRecordField::ParseAssetFromJson(const Json::Value &jvData)
{
    if (!jvData.isObject()) {
        return false;
    }
    MDKAsset asset = ParseAssetFromJsonValue(jvData);
    value_ = asset;
    return true;
}

bool MDKRecordField::ParseReferenceFromJson(const Json::Value &jvData)
{
    if (!jvData.isObject()) {
        return false;
    }
    MDKReference reference;
    reference.recordId = JsonHelper::GetStringFromJson(jvData, "recordId");
    reference.recordType = JsonHelper::GetStringFromJson(jvData, "recordType");
    value_ = reference;
    return true;
}

bool MDKRecordField::ParseFromJsonValue(const MDKSchemaField &schemaField, const Json::Value &jvData)
{
    bool ret = true;
    this->type_ = schemaField.type;
    switch (type_) {
        case MDKRecordFieldType::FIELD_TYPE_NULL:
            break;
        case MDKRecordFieldType::FIELD_TYPE_INT:
            ret = ParseIntFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_DOUBLE:
            ret = ParseDoubleFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_STRING:
            ret = ParseStringFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_BOOL:
            ret = ParseBoolFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_BLOB:
            ret = ParseBlobFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_LIST:
            ret = ParseListFromJson(schemaField.listType, jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_MAP:
            ret = ParseMapFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_ASSET:
            ret = ParseAssetFromJson(jvData);
            break;
        case MDKRecordFieldType::FIELD_TYPE_REFERENCE:
            ret = ParseReferenceFromJson(jvData);
            break;
        default: {
            ret = false;
            break;
        }
    }
    return ret;
}

MDKAsset MDKRecordField::ParseAssetFromJsonValue(const Json::Value &jvData)
{
    MDKAsset asset;
    asset.uri = JsonHelper::GetStringFromJson(jvData, "uri");
    asset.assetName = JsonHelper::GetStringFromJson(jvData, "assetName");
    int value = JsonHelper::GetIntFromJson(jvData, "assetOperType", -1);
    if (value >= static_cast<int> (MDKAssetOperType::DK_ASSET_NONE) &&
        value < static_cast<int> (MDKAssetOperType::DK_ASSET_MAX)) {
        asset.operationType = static_cast<MDKAssetOperType>(value);
    }
    asset.hash = JsonHelper::GetStringFromJson(jvData, "sha256");
    asset.version = JsonHelper::GetInt64FromJson(jvData, "version");
    asset.assetId = JsonHelper::GetStringFromJson(jvData, "assetId");
    asset.subPath = JsonHelper::GetStringFromJson(jvData, "subPath");
    asset.exCheckInfo = JsonHelper::GetStringFromJson(jvData, "exCheckInfo");
    asset.size = JsonHelper::GetUInt64FromJson(jvData, "size");
    asset.fd = JsonHelper::GetIntFromJson(jvData, "fd", -1);
    return asset;
}
// LCOV_EXCL_STOP
}  // namespace OHOS::Media::CloudSync