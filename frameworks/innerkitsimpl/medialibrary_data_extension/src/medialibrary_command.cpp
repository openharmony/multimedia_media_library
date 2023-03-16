/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "medialibrary_command.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_errno.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
MediaLibraryCommand::MediaLibraryCommand(const Uri &uri)
{
    uri_ = uri;
    ParseOprnObjectFromUri();
    ParseOprnTypeFromUri();
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri, const ValuesBucket &value)
{
    uri_ = uri;
    ParseOprnObjectFromUri();
    ParseOprnTypeFromUri();
    ParseTableName();
    insertValue_ = value;
}

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri, const OperationType &oprnType)
{
    uri_ = uri;
    ParseOprnObjectFromUri();
    SetOprnType(oprnType);
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType)
{
    SetOprnObject(oprnObject);
    SetOprnType(oprnType);
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
    const ValuesBucket &value)
{
    SetOprnObject(oprnObject);
    SetOprnType(oprnType);
    ParseTableName();
    insertValue_ = value;
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
    const string &networkId)
{
    SetOprnObject(oprnObject);
    SetOprnType(oprnType);
    SetOprnDevice(networkId);
    ParseTableName();
}

MediaLibraryCommand::~MediaLibraryCommand() {}

// set functions
void MediaLibraryCommand::SetOprnObject(const OperationObject &oprnObject)
{
    oprnObject_ = oprnObject;
}

void MediaLibraryCommand::SetOprnType(const OperationType &oprnType)
{
    oprnType_ = oprnType;
}

void MediaLibraryCommand::SetOprnAssetId(const std::string &oprnId)
{
    oprnFileId_ = oprnId;
}

void MediaLibraryCommand::SetOprnDevice(const std::string &networkId)
{
    oprnDevice_ = networkId;
}

void MediaLibraryCommand::SetValueBucket(const NativeRdb::ValuesBucket &value)
{
    insertValue_ = value;
}

void MediaLibraryCommand::SetTableName(const std::string &tableName)
{
    tableName_ = tableName;
}

// get functions
OperationObject MediaLibraryCommand::GetOprnObject() const
{
    return oprnObject_;
}

OperationType MediaLibraryCommand::GetOprnType() const
{
    return oprnType_;
}

ValuesBucket &MediaLibraryCommand::GetValueBucket()
{
    return insertValue_;
}

AbsRdbPredicates *MediaLibraryCommand::GetAbsRdbPredicates()
{
    if (absRdbPredicates_ == nullptr) {
        InitAbsRdbPredicates();
    }
    return absRdbPredicates_.get();
}

const string &MediaLibraryCommand::GetTableName()
{
    if (tableName_.empty()) {
        ParseTableName();
    }

    return tableName_;
}

const string &MediaLibraryCommand::GetOprnFileId()
{
    if (oprnFileId_.empty()) {
        ParseFileId();
    }

    return oprnFileId_;
}

const string &MediaLibraryCommand::GetOprnDevice()
{
    if (oprnDevice_.empty()) {
        oprnDevice_ = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri_.ToString());
        MEDIA_INFO_LOG("oprnDevice_: %{private}s", oprnDevice_.c_str());
    }
    return oprnDevice_;
}

const Uri &MediaLibraryCommand::GetUri() const
{
    return uri_;
}

void MediaLibraryCommand::ParseOprnObjectFromUri()
{
    string uri = uri_.ToString();

    const static map<string, OperationObject> oprnMap = {
        // use in Insert...
        { MEDIA_FILEOPRN, OperationObject::FILESYSTEM_ASSET },
        { MEDIA_DIROPRN, OperationObject::FILESYSTEM_DIR },
        { MEDIA_ALBUMOPRN, OperationObject::FILESYSTEM_ALBUM },
        { MEDIA_SMARTALBUMOPRN, OperationObject::SMART_ALBUM },
        { MEDIA_SMARTALBUMMAPOPRN, OperationObject::SMART_ALBUM_MAP },
        { THU_OPRN_GENERATES, OperationObject::THUMBNAIL },
        { THU_OPRN_AGING, OperationObject::THUMBNAIL },
        { DISTRIBUTE_THU_OPRN_AGING, OperationObject::THUMBNAIL },
        { DISTRIBUTE_THU_OPRN_CREATE, OperationObject::THUMBNAIL },
        { BUNDLE_PERMISSION_INSERT, OperationObject::BUNDLE_PERMISSION },

        // use in Query...
        { MEDIATYPE_DIRECTORY_TABLE, OperationObject::FILESYSTEM_DIR },
        { MEDIA_DATA_DB_THUMBNAIL, OperationObject::THUMBNAIL },
        { SMARTABLUMASSETS_VIEW_NAME, OperationObject::SMART_ABLUM_ASSETS },
        { ASSETMAP_VIEW_NAME, OperationObject::ASSETMAP },
        { MEDIA_DEVICE_QUERYALLDEVICE, OperationObject::ALL_DEVICE },
        { MEDIA_DEVICE_QUERYACTIVEDEVICE, OperationObject::ACTIVE_DEVICE },
        { MEDIA_ALBUMOPRN_QUERYALBUM, OperationObject::FILESYSTEM_ALBUM },
        { SMARTALBUM_TABLE, OperationObject::SMART_ALBUM },
        { SMARTALBUM_MAP_TABLE, OperationObject::SMART_ALBUM_MAP },
        { MEDIA_QUERYOPRN_QUERYVOLUME, OperationObject::MEDIA_VOLUME },
        { BUNDLE_PERMISSION_TABLE, OperationObject::BUNDLE_PERMISSION },
    };

    for (const auto &item : oprnMap) {
        if (uri.find(item.first) != string::npos) {
            oprnObject_ = item.second;
            break;
        }
    }
}

void MediaLibraryCommand::ParseOprnTypeFromUri()
{
    string insertUri = uri_.ToString();
    auto found = insertUri.rfind('/');
    if (found == string::npos) {
        return;
    }
    string oprnName = insertUri.substr(found + 1);
    const static map<string, OperationType> oprnTypeMap = {
        { MEDIA_FILEOPRN_CLOSEASSET, OperationType::CLOSE },
        { MEDIA_FILEOPRN_CREATEASSET, OperationType::CREATE },
        { MEDIA_ALBUMOPRN_CREATEALBUM, OperationType::CREATE },
        { MEDIA_FILEOPRN_DELETEASSET, OperationType::DELETE },
        { MEDIA_ALBUMOPRN_DELETEALBUM, OperationType::DELETE },
        { MEDIA_FILEOPRN_MODIFYASSET, OperationType::UPDATE },
        { MEDIA_ALBUMOPRN_MODIFYALBUM, OperationType::UPDATE },
        { MEDIA_ALBUMOPRN_QUERYALBUM, OperationType::QUERY },
        { MEDIA_FILEOPRN_ISDIRECTORY, OperationType::ISDICTIONARY },
        { MEDIA_FILEOPRN_GETALBUMCAPACITY, OperationType::QUERY },
        { MEDIA_QUERYOPRN_QUERYVOLUME, OperationType::QUERY },
        { MEDIA_BOARDCASTOPRN, OperationType::SCAN },
        { THU_OPRN_GENERATES, OperationType::GENERATE },
        { THU_OPRN_AGING, OperationType::AGING },
        { DISTRIBUTE_THU_OPRN_AGING, OperationType::DISTRIBUTE_AGING },
        { DISTRIBUTE_THU_OPRN_CREATE, OperationType::DISTRIBUTE_CREATE },
        { BUNDLE_PERMISSION_INSERT, OperationType::INSERT_PERMISSION }
    };

    if (oprnTypeMap.find(oprnName) != oprnTypeMap.end()) {
        oprnType_ = oprnTypeMap.at(oprnName);
    }
    MEDIA_DEBUG_LOG("Command operation type is %{public}d", oprnType_);
}

void MediaLibraryCommand::ParseTableName()
{
    static const map<OperationObject, map<OperationType, string>> tableNameMap = {
        { OperationObject::SMART_ALBUM, { { OperationType::UNKNOWN_TYPE, SMARTALBUM_TABLE } } },
        { OperationObject::SMART_ALBUM_MAP, { { OperationType::UNKNOWN_TYPE, SMARTALBUM_MAP_TABLE } } },
        { OperationObject::SMART_ABLUM_ASSETS, { { OperationType::UNKNOWN_TYPE, SMARTABLUMASSETS_VIEW_NAME } } },
        { OperationObject::ASSETMAP, { { OperationType::UNKNOWN_TYPE, ASSETMAP_VIEW_NAME } } },
        { OperationObject::FILESYSTEM_DIR, { { OperationType::QUERY, MEDIATYPE_DIRECTORY_TABLE } } },
        { OperationObject::FILESYSTEM_ALBUM, { { OperationType::QUERY, ABLUM_VIEW_NAME } } },
        { OperationObject::ALL_DEVICE, { { OperationType::UNKNOWN_TYPE, DEVICE_TABLE } } },
        { OperationObject::ACTIVE_DEVICE, { { OperationType::UNKNOWN_TYPE, DEVICE_TABLE } } },
        { OperationObject::BUNDLE_PERMISSION, { { OperationType::UNKNOWN_TYPE, BUNDLE_PERMISSION_TABLE } } },
    };

    if (tableNameMap.find(oprnObject_) != tableNameMap.end()) {
        auto cmdObj = tableNameMap.at(oprnObject_);
        if (cmdObj.find(oprnType_) != cmdObj.end()) {
            tableName_ = cmdObj.at(oprnType_);
        } else if (cmdObj.find(OperationType::UNKNOWN_TYPE) != cmdObj.end()) {
            tableName_ = cmdObj.at(OperationType::UNKNOWN_TYPE);
        } else {
            tableName_ = MEDIALIBRARY_TABLE;
        }
    } else {
        tableName_ = MEDIALIBRARY_TABLE;
    }

    // distributed tablename
    auto networkId = GetOprnDevice();
    if (networkId.empty()) {
        return;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore != nullptr) {
        auto rdbStorePtr = rdbStore->GetRaw();
        int errCode = E_ERR;
        if (rdbStorePtr != nullptr) {
            tableName_ = rdbStorePtr->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE, errCode);
        }
    }
    MEDIA_INFO_LOG("Table name is %{public}s", tableName_.c_str());
}

void MediaLibraryCommand::InitAbsRdbPredicates()
{
    if (tableName_.empty()) {
        ParseTableName();
    }
    absRdbPredicates_ = make_unique<AbsRdbPredicates>(tableName_);
}

void MediaLibraryCommand::ParseFileId()
{
    int32_t fileIdInValue = -1;
    ValueObject valueObject;
    if (insertValue_.GetObject(MEDIA_DATA_DB_ID, valueObject)) {
        valueObject.GetInt(fileIdInValue);
    }
    if (fileIdInValue != -1) {
        oprnFileId_ = to_string(fileIdInValue);
        return;
    }
    string uriInValue;
    if (insertValue_.GetObject(MEDIA_DATA_DB_URI, valueObject)) {
        valueObject.GetString(uriInValue);
    }
    if (uriInValue.empty()) {
        uriInValue = uri_.ToString();
    }
    MediaLibraryDataManagerUtils::RemoveTypeValueFromUri(uriInValue);
    string idFromUri = MediaLibraryDataManagerUtils::GetIdFromUri(uriInValue);
    if (!MediaLibraryDataManagerUtils::IsNumber(idFromUri)) {
        return;
    }
    oprnFileId_ = idFromUri;
}
} // namespace Media
} // namespace OHOS
