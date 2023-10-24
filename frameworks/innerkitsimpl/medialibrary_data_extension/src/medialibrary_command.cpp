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

#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_db_const.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_map_column.h"
#include "medialibrary_errno.h"
#include "userfilemgr_uri.h"
#include "vision_column.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
namespace {
static const map<string, OperationType> OPRN_TYPE_MAP = {
    { MEDIA_FILEOPRN_CLOSEASSET, OperationType::CLOSE },
    { MEDIA_FILEOPRN_CREATEASSET, OperationType::CREATE },
    { MEDIA_ALBUMOPRN_CREATEALBUM, OperationType::CREATE },
    { MEDIA_FILEOPRN_DELETEASSET, OperationType::DELETE },
    { MEDIA_ALBUMOPRN_DELETEALBUM, OperationType::DELETE },
    { MEDIA_FILEOPRN_MODIFYASSET, OperationType::UPDATE },
    { MEDIA_ALBUMOPRN_MODIFYALBUM, OperationType::UPDATE },
    { MEDIA_ALBUMOPRN_QUERYALBUM, OperationType::QUERY },
    { MEDIA_FILEOPRN_GETALBUMCAPACITY, OperationType::QUERY },
    { MEDIA_QUERYOPRN_QUERYVOLUME, OperationType::QUERY },
    { MEDIA_BOARDCASTOPRN, OperationType::SCAN },
    { OPRN_SCAN, OperationType::SCAN },
    { OPRN_DELETE_BY_TOOL, OperationType::DELETE_TOOL },
    { MEDIA_FILEOPRN_COPYASSET, OperationType::COPY },
    { MEDIA_DIROPRN_DELETEDIR, OperationType::DELETE },
    { MEDIA_DIROPRN_FMS_CREATEDIR, OperationType::CREATE },
    { MEDIA_DIROPRN_FMS_DELETEDIR, OperationType::DELETE },
    { MEDIA_DIROPRN_FMS_TRASHDIR, OperationType::TRASH },
    { MEDIA_SMARTALBUMOPRN_CREATEALBUM, OperationType::CREATE },
    { MEDIA_SMARTALBUMOPRN_DELETEALBUM, OperationType::DELETE },
    { MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM, OperationType::CREATE },
    { MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM, OperationType::DELETE },
    { MEDIA_SMARTALBUMMAPOPRN_AGEINGSMARTALBUM, OperationType::AGING },
    { MEDIA_SMARTALBUMOPRN_MODIFYALBUM, OperationType::UPDATE },
    { BUNDLE_PERMISSION_INSERT, OperationType::INSERT_PERMISSION },
    { OPRN_CREATE, OperationType::CREATE },
    { OPRN_CREATE_COMPONENT, OperationType::CREATE },
    { OPRN_DELETE, OperationType::DELETE },
    { OPRN_QUERY, OperationType::QUERY },
    { OPRN_UPDATE, OperationType::UPDATE },
    { OPRN_ALBUM_ADD_PHOTOS, OperationType::ALBUM_ADD_PHOTOS },
    { OPRN_ALBUM_REMOVE_PHOTOS, OperationType::ALBUM_REMOVE_PHOTOS },
    { OPRN_RECOVER_PHOTOS, OperationType::ALBUM_RECOVER_ASSETS },
    { OPRN_DELETE_PHOTOS, OperationType::ALBUM_DELETE_ASSETS },
    { OPRN_COMPAT_DELETE_PHOTOS, OperationType::COMPAT_ALBUM_DELETE_ASSETS },
    { OPRN_CLOSE, OperationType::CLOSE },
    { OPRN_TRASH, OperationType::TRASH_PHOTO },
    { OPRN_PENDING, OperationType::UPDATE_PENDING },
    { OPRN_SET_USER_COMMENT, OperationType::SET_USER_COMMENT },
    { OPRN_INDEX, OperationType::INDEX },
    { OPRN_COMMIT_EDIT, OperationType::COMMIT_EDIT },
    { OPRN_REVERT_EDIT, OperationType::REVERT_EDIT },
};
}

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri) : uri_(uri)
{
    ParseOprnObjectFromUri();
    ParseOprnTypeFromUri();
    ParseQuerySetMapFromUri();
    SetApiFromQuerySetMap();
    ParseOprnObjectFromFileUri();
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri, const ValuesBucket &value) : uri_(uri), insertValue_(value)
{
    ParseOprnObjectFromUri();
    ParseOprnTypeFromUri();
    ParseQuerySetMapFromUri();
    SetApiFromQuerySetMap();
    ParseOprnObjectFromFileUri();
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const Uri &uri, const OperationType &oprnType) : uri_(uri), oprnType_(oprnType)
{
    ParseOprnObjectFromUri();
    ParseQuerySetMapFromUri();
    SetApiFromQuerySetMap();
    ParseOprnObjectFromFileUri();
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
    MediaLibraryApi api) : oprnObject_(oprnObject), oprnType_(oprnType), api_(api)
{
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
    const ValuesBucket &value, MediaLibraryApi api) :insertValue_(value), oprnObject_(oprnObject),
    oprnType_(oprnType), api_(api)
{
    ParseTableName();
}

MediaLibraryCommand::MediaLibraryCommand(const OperationObject &oprnObject, const OperationType &oprnType,
    const string &networkId, MediaLibraryApi api) : oprnObject_(oprnObject), oprnType_(oprnType),
    oprnDevice_(networkId), api_(api)
{
    ParseTableName();
}

MediaLibraryCommand::~MediaLibraryCommand() {}

// set functions
void MediaLibraryCommand::SetOprnObject(OperationObject object)
{
    oprnObject_ = object;
}

void MediaLibraryCommand::SetOprnAssetId(const std::string &oprnId)
{
    oprnFileId_ = oprnId;
}

void MediaLibraryCommand::SetValueBucket(const NativeRdb::ValuesBucket &value)
{
    insertValue_ = value;
}

void MediaLibraryCommand::SetTableName(const std::string &tableName)
{
    tableName_ = tableName;
}

void MediaLibraryCommand::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

void MediaLibraryCommand::SetDeviceName(const std::string &deviceName)
{
    deviceName_ = deviceName;
}

void MediaLibraryCommand::SetResult(const std::string &result)
{
    result_ = result;
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
    }
    return oprnDevice_;
}

const Uri &MediaLibraryCommand::GetUri() const
{
    return uri_;
}

const string &MediaLibraryCommand::GetBundleName()
{
    return bundleName_;
}

const string &MediaLibraryCommand::GetDeviceName()
{
    return deviceName_;
}

const string &MediaLibraryCommand::GetResult()
{
    return result_;
}

string MediaLibraryCommand::GetUriStringWithoutSegment() const
{
    string uriString = uri_.ToString();
    size_t questionMaskPoint = uriString.rfind('?');
    size_t hashKeyPoint = uriString.rfind('#');
    if (questionMaskPoint != string::npos) {
        return uriString.substr(0, questionMaskPoint);
    }
    if (hashKeyPoint != string::npos) {
        return uriString.substr(0, hashKeyPoint);
    }
    return uriString;
}

MediaLibraryApi MediaLibraryCommand::GetApi()
{
    return api_;
}

string MediaLibraryCommand::GetQuerySetParam(const std::string &key)
{
    if (key.empty() || querySetMap_.find(key) == querySetMap_.end()) {
        return "";
    }
    return querySetMap_[key];
}

void MediaLibraryCommand::ParseOprnObjectFromUri()
{
    static const map<string, OperationObject> OPRN_OBJ_MAP = {
        // use in Insert...
        { MEDIA_FILEOPRN, OperationObject::FILESYSTEM_ASSET },
        { MEDIA_PHOTOOPRN, OperationObject::FILESYSTEM_PHOTO },
        { MEDIA_AUDIOOPRN, OperationObject::FILESYSTEM_AUDIO },
        { MEDIA_DIROPRN, OperationObject::FILESYSTEM_DIR },
        { MEDIA_ALBUMOPRN, OperationObject::FILESYSTEM_ALBUM },
        { MEDIA_SMARTALBUMOPRN, OperationObject::SMART_ALBUM },
        { MEDIA_SMARTALBUMMAPOPRN, OperationObject::SMART_ALBUM_MAP },
        { BUNDLE_PERMISSION_INSERT, OperationObject::BUNDLE_PERMISSION },
        { PHOTO_ALBUM_OPRN, OperationObject::PHOTO_ALBUM },
        { PHOTO_MAP_OPRN, OperationObject::PHOTO_MAP },
        { UFM_PHOTO, OperationObject::UFM_PHOTO },
        { UFM_AUDIO, OperationObject::UFM_AUDIO },
        { UFM_ALBUM, OperationObject::UFM_ALBUM },
        { UFM_MAP, OperationObject::UFM_MAP },
        { PAH_PHOTO, OperationObject::PAH_PHOTO },
        { PAH_ALBUM, OperationObject::PAH_ALBUM },
        { PAH_MAP, OperationObject::PAH_MAP },
        { TOOL_PHOTO, OperationObject::TOOL_PHOTO },
        { TOOL_AUDIO, OperationObject::TOOL_AUDIO },

        // use in Query...
        { MEDIATYPE_DIRECTORY_TABLE, OperationObject::FILESYSTEM_DIR },
        { MEDIA_DATA_DB_THUMBNAIL, OperationObject::THUMBNAIL },
        { SMARTALBUMASSETS_VIEW_NAME, OperationObject::SMART_ALBUM_ASSETS },
        { ASSETMAP_VIEW_NAME, OperationObject::ASSETMAP },
        { MEDIA_DEVICE_QUERYALLDEVICE, OperationObject::ALL_DEVICE },
        { MEDIA_DEVICE_QUERYACTIVEDEVICE, OperationObject::ACTIVE_DEVICE },
        { MEDIA_ALBUMOPRN_QUERYALBUM, OperationObject::FILESYSTEM_ALBUM },
        { SMARTALBUM_TABLE, OperationObject::SMART_ALBUM },
        { SMARTALBUM_MAP_TABLE, OperationObject::SMART_ALBUM_MAP },
        { MEDIA_QUERYOPRN_QUERYVOLUME, OperationObject::MEDIA_VOLUME },

        // use in Vision
        { VISION_OCR_TABLE, OperationObject::VISION_OCR },
        { VISION_LABEL_TABLE, OperationObject::VISION_LABEL },
        { VISION_AESTHETICS_TABLE, OperationObject::VISION_AESTHETICS },
        { VISION_TOTAL_TABLE, OperationObject::VISION_TOTAL },
        { VISION_SHIELD_TABLE, OperationObject::VISION_SHIELD },
    };

    const string opObject = MediaFileUri::GetPathFirstDentry(uri_);
    if (OPRN_OBJ_MAP.find(opObject) != OPRN_OBJ_MAP.end()) {
        oprnObject_ = OPRN_OBJ_MAP.at(opObject);
    }
    MEDIA_DEBUG_LOG("Command operation object is %{public}d", oprnObject_);
}

void MediaLibraryCommand::ParseOprnTypeFromUri()
{
    const string opType = MediaFileUri::GetPathSecondDentry(uri_);
    if (OPRN_TYPE_MAP.find(opType) != OPRN_TYPE_MAP.end()) {
        oprnType_ = OPRN_TYPE_MAP.at(opType);
    } else {
        oprnType_ = OperationType::QUERY;
    }
    MEDIA_DEBUG_LOG("Command operation type is %{public}d", oprnType_);
}

static string GetDistTable(const string &table, const string &networkId)
{
    string ret = MEDIALIBRARY_TABLE;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return ret;
    }
    auto rdbStorePtr = rdbStore->GetRaw();
    if (rdbStorePtr == nullptr) {
        return ret;
    }

    int errCode = E_ERR;
    if (table == PhotoColumn::PHOTOS_TABLE || table == AudioColumn::AUDIOS_TABLE) {
        ret = rdbStorePtr->ObtainDistributedTableName(networkId, table, errCode);
    } else {
        ret = rdbStorePtr->ObtainDistributedTableName(networkId, MEDIALIBRARY_TABLE, errCode);
    }
    return ret;
}

static const map<OperationObject, map<OperationType, string>> TABLE_NAME_MAP = {
    { OperationObject::SMART_ALBUM, { { OperationType::UNKNOWN_TYPE, SMARTALBUM_TABLE } } },
    { OperationObject::SMART_ALBUM_MAP, { { OperationType::UNKNOWN_TYPE, SMARTALBUM_MAP_TABLE } } },
    { OperationObject::SMART_ALBUM_ASSETS, { { OperationType::UNKNOWN_TYPE, SMARTALBUMASSETS_VIEW_NAME } } },
    { OperationObject::ASSETMAP, { { OperationType::UNKNOWN_TYPE, ASSETMAP_VIEW_NAME } } },
    { OperationObject::FILESYSTEM_DIR, { { OperationType::QUERY, MEDIATYPE_DIRECTORY_TABLE } } },
#ifdef MEDIALIBRARY_COMPATIBILITY
    { OperationObject::FILESYSTEM_ALBUM, { { OperationType::QUERY, PhotoAlbumColumns::TABLE } } },
#else
    { OperationObject::FILESYSTEM_ALBUM, { { OperationType::QUERY, ALBUM_VIEW_NAME } } },
#endif
    { OperationObject::ALL_DEVICE, { { OperationType::UNKNOWN_TYPE, DEVICE_TABLE } } },
    { OperationObject::ACTIVE_DEVICE, { { OperationType::UNKNOWN_TYPE, DEVICE_TABLE } } },
    { OperationObject::BUNDLE_PERMISSION, { { OperationType::UNKNOWN_TYPE, BUNDLE_PERMISSION_TABLE } } },
    { OperationObject::FILESYSTEM_PHOTO, { { OperationType::UNKNOWN_TYPE, PhotoColumn::PHOTOS_TABLE } } },
    { OperationObject::FILESYSTEM_AUDIO, { { OperationType::UNKNOWN_TYPE, AudioColumn::AUDIOS_TABLE } } },
    { OperationObject::PHOTO_ALBUM, { { OperationType::UNKNOWN_TYPE, PhotoAlbumColumns::TABLE } } },
    { OperationObject::PHOTO_MAP, { { OperationType::UNKNOWN_TYPE, PhotoMap::TABLE } } },
    { OperationObject::UFM_PHOTO, { { OperationType::UNKNOWN_TYPE, PhotoColumn::PHOTOS_TABLE } } },
    { OperationObject::UFM_AUDIO, { { OperationType::UNKNOWN_TYPE, AudioColumn::AUDIOS_TABLE } } },
    { OperationObject::UFM_ALBUM, { { OperationType::UNKNOWN_TYPE, PhotoAlbumColumns::TABLE } } },
    { OperationObject::UFM_MAP, { { OperationType::UNKNOWN_TYPE, PhotoMap::TABLE } } },
    { OperationObject::PAH_PHOTO, { { OperationType::UNKNOWN_TYPE, PhotoColumn::PHOTOS_TABLE } } },
    { OperationObject::PAH_ALBUM, { { OperationType::UNKNOWN_TYPE, PhotoAlbumColumns::TABLE } } },
    { OperationObject::PAH_MAP, { { OperationType::UNKNOWN_TYPE, PhotoMap::TABLE } } },
    { OperationObject::TOOL_PHOTO, { { OperationType::UNKNOWN_TYPE, PhotoColumn::PHOTOS_TABLE } } },
    { OperationObject::TOOL_AUDIO, { { OperationType::UNKNOWN_TYPE, AudioColumn::AUDIOS_TABLE } } },
    { OperationObject::VISION_OCR, { { OperationType::UNKNOWN_TYPE, VISION_OCR_TABLE } } },
    { OperationObject::VISION_LABEL, { { OperationType::UNKNOWN_TYPE, VISION_LABEL_TABLE } } },
    { OperationObject::VISION_AESTHETICS, { { OperationType::UNKNOWN_TYPE, VISION_AESTHETICS_TABLE } } },
    { OperationObject::VISION_TOTAL, { { OperationType::UNKNOWN_TYPE, VISION_TOTAL_TABLE } } },
    { OperationObject::VISION_SHIELD, { { OperationType::UNKNOWN_TYPE, VISION_SHIELD_TABLE } } },
};

void MediaLibraryCommand::ParseTableName()
{
    if (TABLE_NAME_MAP.find(oprnObject_) != TABLE_NAME_MAP.end()) {
        auto cmdObj = TABLE_NAME_MAP.at(oprnObject_);
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
    // distributed tablename, smartalbum and smartalbumMap can not distributed
    if ((oprnObject_ == OperationObject::SMART_ALBUM) || (oprnObject_ == OperationObject::SMART_ALBUM_MAP)) {
        MEDIA_DEBUG_LOG("smart table name is %{public}s", tableName_.c_str());
        return;
    }
    // distributed tablename
    auto networkId = GetOprnDevice();
    if (networkId.empty()) {
        return;
    }
    tableName_ = GetDistTable(tableName_, networkId);
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
        uriInValue = GetUriStringWithoutSegment();
    }

    string idFromUri = MediaLibraryDataManagerUtils::GetIdFromUri(uriInValue);
    if (!MediaLibraryDataManagerUtils::IsNumber(idFromUri)) {
        return;
    }
    oprnFileId_ = idFromUri;
}

void MediaLibraryCommand::ParseQuerySetMapFromUri()
{
    // uri format: datashare:///media/photo_operation/create_asset?op1=xxx&op2=yyy&api_version=10#abc
    // QuerySetMap: {"op1": "xxx", "op2": "yyy", "api_version": "10"}
    string uriStr = uri_.ToString();
    size_t cutPoint = uriStr.find('#');
    if (cutPoint != string::npos) {
        uriStr = uriStr.substr(0, cutPoint);
    }
    MediaFileUri mediaUri(uriStr);
    querySetMap_ = mediaUri.GetQueryKeys();
}

void MediaLibraryCommand::SetApiFromQuerySetMap()
{
    if (querySetMap_.find(URI_PARAM_API_VERSION) == querySetMap_.end()) {
        api_ = MediaLibraryApi::API_OLD;
    } else {
        string apiString = querySetMap_[URI_PARAM_API_VERSION];
        if (!MediaLibraryDataManagerUtils::IsNumber(apiString)) {
            api_ = MediaLibraryApi::API_OLD;
            return;
        }
        int32_t apiNum = stoi(apiString);
        if (apiNum <= static_cast<int32_t>(MediaLibraryApi::API_START) ||
            apiNum >= static_cast<int32_t>(MediaLibraryApi::API_END)) {
            MEDIA_ERR_LOG("this api num is wrong: %{public}d", apiNum);
            api_ = MediaLibraryApi::API_OLD;
        } else {
            api_ = static_cast<MediaLibraryApi>(apiNum);
        }
    }
}

void MediaLibraryCommand::ParseOprnObjectFromFileUri()
{
    if (oprnObject_ != OperationObject::UNKNOWN_OBJECT) {
        return;
    }

    string uri = uri_.ToString();
    static const map<string, OperationObject> oprnMap = {
        { PhotoColumn::PHOTO_URI_PREFIX, OperationObject::FILESYSTEM_PHOTO },
        { AudioColumn::AUDIO_URI_PREFIX, OperationObject::FILESYSTEM_AUDIO }
    };

    for (const auto &item : oprnMap) {
        if (MediaFileUtils::StartsWith(uri, item.first)) {
            oprnObject_ = item.second;
            break;
        }
    }
}

void MediaLibraryCommand::SetDataSharePred(const DataSharePredicates &pred)
{
    datasharePred_ = make_unique<const DataSharePredicates>(pred);
}

// Caller is responsible for calling SetDataSharePred() firstly, before calling GetDataSharePred()
const DataSharePredicates &MediaLibraryCommand::GetDataSharePred() const
{
    return *datasharePred_;
}
} // namespace Media
} // namespace OHOS
