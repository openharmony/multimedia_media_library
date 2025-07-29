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

#include "medialibrarycloudmediamdkrecord_fuzzer.h"

#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "mdk_record.h"
#include "mdk_record_field.h"
#include "mdk_database.h"
#include "mdk_record_album_data.h"
#include "mdk_record_photos_data.h"
#include "json_helper.h"
#include "cloud_media_album_handler.h"
#include "mdk_record_reader.h"
#undef private
#include "media_log.h"

namespace OHOS {
using namespace std;
using namespace OHOS::Media;
using namespace OHOS::Media::CloudSync;
const int32_t NAME_LEN = 1;
const int32_t LIST_SIZE = 10;
const int32_t DATA_BYTES = 1024;
FuzzedDataProvider* provider;

static Json::Value FuzzParseJvData()
{
    Json::Value jvData(Json::objectValue);
    jvData["recordId"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["recordType"] = "fuzz";
    jvData["deleted"] = provider->ConsumeBool();
    jvData["isNew"] = provider->ConsumeBool();
    jvData["version"] = provider->ConsumeIntegral<int64_t>();
    jvData["createdTime"] = provider->ConsumeIntegral<uint64_t>();
    jvData["editedTime"] = provider->ConsumeIntegral<uint64_t>();
    jvData["ownerId"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["shareUri"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["privilege"] = provider->ConsumeIntegral<uint32_t>();
    jvData["isShared"] = provider->ConsumeBool();
    Json::Value jvRecordData(Json::objectValue);
    jvRecordData["fuzzString"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvRecordData["fuzzInteger"] = provider->ConsumeIntegral<uint64_t>();
    jvData["record"] = jvRecordData;
    return jvData;
}

static Json::Value FuzzCreateInfoJvData()
{
    Json::Value jvData(Json::objectValue);
    jvData["createInfo"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["appId"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["deviceName"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["time"] = provider->ConsumeBytesAsString(NAME_LEN);
    return jvData;
}

static Json::Value FuzzModifyInfoJvData()
{
    Json::Value jvData(Json::objectValue);
    jvData["modifiedInfo"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["appId"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["deviceName"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["time"] = provider->ConsumeBytesAsString(NAME_LEN);
    return jvData;
}

static MDKSchema FuzzSchemaData()
{
    MDKSchema schema;
    MDKSchemaNode fuzzSchemaNode;
    MDKSchemaField stringField;
    stringField.name = "fuzzString";
    stringField.type = MDKRecordFieldType::FIELD_TYPE_STRING;
    MDKSchemaField integerField;
    integerField.name = "fuzzInteger";
    integerField.type = MDKRecordFieldType::FIELD_TYPE_INT;
    fuzzSchemaNode.fields["fuzzString"] = stringField;
    fuzzSchemaNode.fields["fuzzInteger"] = integerField;
    schema.recordTypes["fuzz"] = fuzzSchemaNode;
    return schema;
}

static void MdkRecordFuzzer()
{
    MDKRecord record;
    record.SetRecordId(provider->ConsumeBytesAsString(NAME_LEN));
    record.GetRecordId();
    record.SetRecordType(provider->ConsumeBytesAsString(NAME_LEN));
    record.GetRecordType();
    std::map<std::string, MDKRecordField> field;
    record.SetRecordData(field);
    record.GetRecordData(field);
    record.SetDelete(provider->ConsumeBool());
    record.GetIsDelete();
    record.SetNewCreate(provider->ConsumeBool());
    record.GetNewCreate();
    record.SetVersion(provider->ConsumeIntegral<int64_t>());
    record.SetCreateTime(provider->ConsumeIntegral<uint64_t>());
    record.GetCreateTime();
    record.SetEditedTime(provider->ConsumeIntegral<uint64_t>());
    record.GetEditedTime();
    record.SetOwnerId(provider->ConsumeBytesAsString(NAME_LEN));
    record.GetOwnerId();
    record.GetShared();
    record.SetShared(provider->ConsumeBool());
    record.GetShared();
    record.SetSrcRecordId(provider->ConsumeBytesAsString(NAME_LEN));
    record.GetSrcRecordId();
    MDKRecordsResponse create;
    record.SetCreateInfo(create);
    record.GetRecordCreateInfo();
    MDKRecordsResponse modified;
    record.SetModifiedInfo(modified);
    record.GetRecordModifiedInfo();
    record.GetPrivilege();
    std::vector<MDKRelation> relations;
    record.SetRecordRelations(relations);
    record.GetRecordRelations(relations);
    record.SetBaseCursor(provider->ConsumeBytesAsString(NAME_LEN));
    record.ToJsonValue();
    record.ParseFromJsonValue(FuzzSchemaData(), FuzzParseJvData());
    MDKRecordField listField;
    record.AssetListToJsonValue(listField);
    record.ParseCreateInfoFromJson(FuzzCreateInfoJvData());
    record.ParseModifyInfoFromJson(FuzzModifyInfoJvData());
}

static void MdkRecordFieldSimpleTypeParseFromJsonValueFuzzer()
{
    MDKRecordField recordField;
    MDKSchemaField schemaField;
    Json::Value jvData;

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_NULL;
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_INT;
    jvData = provider->ConsumeIntegral<int64_t>();
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_DOUBLE;
    jvData = provider->ConsumeFloatingPoint<double>();
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_STRING;
    jvData = provider->ConsumeBytesAsString(NAME_LEN);
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_BOOL;
    jvData = provider->ConsumeBool();
    recordField.ParseFromJsonValue(schemaField, jvData);
}

static void MdkRecordFieldComplexTypeParseFromJsonValueFuzzer()
{
    MDKRecordField recordField;
    MDKSchemaField schemaField;
    Json::Value jvData;

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_BLOB;
    std::vector<uint8_t> blobData =
        provider->ConsumeBytes<uint8_t>(provider->ConsumeIntegralInRange<size_t>(0, DATA_BYTES));
    jvData = Json::Value(Json::arrayValue);
    for (uint8_t byte : blobData) {
        jvData.append(static_cast<int>(byte));
    }
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_LIST;
    size_t listSize = provider->ConsumeIntegralInRange<size_t>(0, LIST_SIZE);
    jvData = Json::Value(Json::arrayValue);
    for (size_t i = 0; i < listSize; ++i) {
        jvData.append(provider->ConsumeIntegral<int64_t>());
    }
    schemaField.listType = MDKRecordFieldType::FIELD_TYPE_INT;
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_MAP;
    jvData = Json::Value(Json::objectValue);
    jvData["intField"] = provider->ConsumeIntegral<int64_t>();
    jvData["doubleField"] = provider->ConsumeFloatingPoint<double>();
    jvData["stringField"] = provider->ConsumeBytesAsString(NAME_LEN);
    jvData["boolField"] = provider->ConsumeBool();
    jvData["unsupportedField"] = Json::Value(Json::arrayValue);
    jvData["unsupportedField"].append(1);
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_ASSET;
    recordField.ParseFromJsonValue(schemaField, jvData);

    schemaField.type = MDKRecordFieldType::FIELD_TYPE_REFERENCE;
    recordField.ParseFromJsonValue(schemaField, jvData);
}

static void MdkRecordFieldToJsonValueFuzzer()
{
    MDKRecordField recordField;

    recordField.GetType();
    recordField.GetFieldValue();

    recordField.type_ = MDKRecordFieldType::FIELD_TYPE_INT;
    recordField.value_ = provider->ConsumeIntegral<int64_t>();
    int intVal;
    recordField.GetInt(intVal);
    int64_t int64Val;
    recordField.GetLong(int64Val);
    recordField.ToJsonValue();

    recordField.type_ = MDKRecordFieldType::FIELD_TYPE_DOUBLE;
    recordField.value_ = provider->ConsumeFloatingPoint<double>();
    double doubleVal;
    recordField.GetDouble(doubleVal);
    recordField.ToJsonValue();

    recordField.type_ = MDKRecordFieldType::FIELD_TYPE_BOOL;
    recordField.value_ = provider->ConsumeBool();
    bool boolVal;
    recordField.GetBool(boolVal);
    recordField.ToJsonValue();

    recordField.type_ = MDKRecordFieldType::FIELD_TYPE_STRING;
    recordField.value_ = provider->ConsumeBytesAsString(NAME_LEN);
    std::string stringVal;
    recordField.GetString(stringVal);
    recordField.ToJsonValue();

    std::vector<uint8_t> blobVal;
    recordField.type_ = MDKRecordFieldType::FIELD_TYPE_BLOB;
    recordField.value_ = provider->ConsumeBytes<uint8_t>(provider->ConsumeIntegralInRange<size_t>(0, DATA_BYTES));
    recordField.GetBlob(blobVal);
    recordField.ToJsonValue();
}

static void MdkRecordReaderFuzzer()
{
    std::map<std::string, MDKRecordField> fields;
    MDKRecordField field;
    fields["empty_value_key"] = field;
    MDKRecordReader reader;
    reader.GetAssetValue(fields, "empty_value_key");
    reader.GetStringValue(fields, "empty_value_key");
    reader.GetLongValue(fields, "empty_value_key");
    reader.GetIntValue(fields, "empty_value_key");
    reader.GetBoolValue(fields, "empty_value_key");
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    if (data == nullptr) {
        return 0;
    }
    OHOS::provider = &fdp;
    OHOS::MdkRecordFuzzer();
    OHOS::MdkRecordFieldSimpleTypeParseFromJsonValueFuzzer();
    OHOS::MdkRecordFieldComplexTypeParseFromJsonValueFuzzer();
    OHOS::MdkRecordFieldToJsonValueFuzzer();
    OHOS::MdkRecordReaderFuzzer();
    return 0;
}