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

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri, const OperationType oprnType)
{
    uri_ = uri;
    ParseOprnObjectFromUri();
    SetOprnType(oprnType);
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject oprnObject, const OperationType oprnType)
{
    SetOprnObject(oprnObject);
    SetOprnType(oprnType);
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject oprnObject, const OperationType oprnType,
                                         const ValuesBucket &value)
{
    SetOprnObject(oprnObject);
    SetOprnType(oprnType);
    ParseTableName();
    insertValue_ = value;
}

MediaLibraryCommand::~MediaLibraryCommand() {}

// set functions
void MediaLibraryCommand::SetOprnObject(const OperationObject oprnObject)
{
    oprnObject_ = oprnObject;
}

void MediaLibraryCommand::SetOprnType(const OperationType oprnType)
{
    oprnType_ = oprnType;
}

void MediaLibraryCommand::SetOprnAssetId(const std::string &oprnId)
{
    oprnFileId_ = oprnId;
}

void MediaLibraryCommand::SetOprnDevice(const std::string &deviceId)
{
    oprnDevice_ = deviceId;
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

const ValuesBucket &MediaLibraryCommand::GetValueBucket() const
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
    MEDIA_INFO_LOG("uri: %{public}s", uri.c_str());

    const static map<string, OperationObject> oprnMap = {
        // use in Insert...
        {MEDIA_FILEOPRN, FILESYSTEM_ASSET},
        {MEDIA_DIROPRN, FILESYSTEM_DIR},
        {MEDIA_ALBUMOPRN, FILESYSTEM_ALBUM},
        {MEDIA_SMARTALBUMOPRN, SMART_ALBUM},
        {MEDIA_SMARTALBUMMAPOPRN, SMART_ALBUM_MAP},
        {MEDIA_KVSTOREOPRN, KVSTORE},
        // use in Query...
        {MEDIATYPE_DIRECTORY_TABLE, FILESYSTEM_DIR},
        {MEDIA_DATA_DB_THUMBNAIL, THUMBNAIL},
        {SMARTABLUMASSETS_VIEW_NAME, SMART_ABLUM_ASSETS},
        {ASSETMAP_VIEW_NAME, ASSETMAP},
        {MEDIA_DEVICE_QUERYALLDEVICE, ALL_DEVICE},
        {MEDIA_DEVICE_QUERYACTIVEDEVICE, ACTIVE_DEVICE},
        {MEDIA_ALBUMOPRN_QUERYALBUM, FILESYSTEM_ALBUM},
        {SMARTALBUM_TABLE, SMART_ALBUM},
        {SMARTALBUM_MAP_TABLE, SMART_ALBUM_MAP},
        {MEDIA_QUERYOPRN_QUERYVOLUME, MEDIA_VOLUME},
    };

    for (const auto &item : oprnMap) {
        if (uri.find(item.first) != string::npos) {
            oprnObject_ = item.second;
            break;
        }
    }

    MEDIA_INFO_LOG("Command operation object is %{public}d", oprnObject_);
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
        {MEDIA_FILEOPRN_CLOSEASSET, CLOSE},
        {MEDIA_FILEOPRN_CREATEASSET, CREATE},
        {MEDIA_ALBUMOPRN_CREATEALBUM, CREATE},
        {MEDIA_FILEOPRN_DELETEASSET, DELETE},
        {MEDIA_ALBUMOPRN_DELETEALBUM, DELETE},
        {MEDIA_FILEOPRN_MODIFYASSET, UPDATE},
        {MEDIA_ALBUMOPRN_MODIFYALBUM, UPDATE},
        {MEDIA_ALBUMOPRN_QUERYALBUM, QUERY},
        {MEDIA_FILEOPRN_ISDIRECTORY, ISDICTIONARY},
        {MEDIA_FILEOPRN_GETALBUMCAPACITY, QUERY},
        {MEDIA_QUERYOPRN_QUERYVOLUME, QUERY},
        {MEDIA_BOARDCASTOPRN, SCAN}
    };

    if (oprnTypeMap.find(oprnName) != oprnTypeMap.end()) {
        oprnType_ = oprnTypeMap.at(oprnName);
    }
    MEDIA_INFO_LOG("Command operation type is %{public}d", oprnType_);
    return;
}

void MediaLibraryCommand::ParseTableName()
{
    static const map<OperationObject, map<OperationType, string>> tableNameMap = {
        {SMART_ALBUM, {{UNKNOWN_TYPE, SMARTALBUM_TABLE}}},
        {SMART_ALBUM_MAP, {{UNKNOWN_TYPE, SMARTALBUM_MAP_TABLE}}},
        {SMART_ABLUM_ASSETS, {{UNKNOWN_TYPE, SMARTABLUMASSETS_VIEW_NAME}}},
        {ASSETMAP, {{UNKNOWN_TYPE, ASSETMAP_VIEW_NAME}}},
        {FILESYSTEM_DIR, {{QUERY, MEDIATYPE_DIRECTORY_TABLE}}},
        {FILESYSTEM_ALBUM, {{QUERY, ABLUM_VIEW_NAME}}},
        {ALL_DEVICE, {{UNKNOWN_TYPE, DEVICE_TABLE}}},
        {ACTIVE_DEVICE, {{UNKNOWN_TYPE, DEVICE_TABLE}}},
    };

    if (tableNameMap.find(oprnObject_) != tableNameMap.end()) {
        if (tableNameMap.at(oprnObject_).find(oprnType_) != tableNameMap.at(oprnObject_).end()) {
            tableName_ = tableNameMap.at(oprnObject_).at(oprnType_);
        } else if (tableNameMap.at(oprnObject_).find(UNKNOWN_TYPE) != tableNameMap.at(oprnObject_).end()) {
            tableName_ = tableNameMap.at(oprnObject_).at(UNKNOWN_TYPE);
        } else {
            tableName_ = MEDIALIBRARY_TABLE;
        }
    } else {
        tableName_ = MEDIALIBRARY_TABLE;
    }

    // distributed tablename
    auto deviceId = GetOprnDevice();
    if (!deviceId.empty()) {
        auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
        if (rdbStore != nullptr) {
            tableName_ = rdbStore->ObtainDistributedTableName(deviceId, MEDIALIBRARY_TABLE);
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
    MEDIA_INFO_LOG("ParseFileId: uriInValue is %{public}s", uriInValue.c_str());
    string idFromUri = MediaLibraryDataManagerUtils::GetIdFromUri(uriInValue);
    if (!MediaLibraryDataManagerUtils::IsNumber(idFromUri)) {
        return;
    }
    oprnFileId_ = idFromUri;
}
} // namespace Media
} // namespace OHOS